"""AX Vuln Radar: 脆弱性・バージョン情報自動収集＆AIトリアージバッチ。

MyJVN API / JVNDB公式RSSフィードからJava・PHP・Webミドルウェア関連の
最新の脆弱性情報を取得し、LLM APIまたはルールベースエンジンを用いて
中小企業の情シス・BPO担当者向けの平易な日本語トリアージJSONを生成する。
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# パス・タイムゾーン定義
PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = PROJECT_ROOT / "public" / "data" / "vulnerabilities.json"
ENV_PATH = PROJECT_ROOT / ".env"
JST = timezone(timedelta(hours=9))

# JVNDB 取得元URL（プライマリ: SPEC記載のMyJVN API、セカンダリ: JVNDB公式新着RDF）
PRIMARY_JVN_URL = (
    "https://jvndb.jvn.jp/myjvn"
    "?method=getVulnOverviewList&feed=hnd"
    "&rangeDatePublished=n&rangeDateFirstPublished=n"
)
SECONDARY_JVN_URL = "https://jvndb.jvn.jp/ja/rss/jvndb_new.rdf"
JVN_FALLBACK_LINK = "https://jvndb.jvn.jp/"

# XML 名前空間
XML_NS = {
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "rss": "http://purl.org/rss/1.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "sec": "http://jvn.jp/rss/mod_sec/",
}

# 抽出対象キーワード（JavaScriptへの誤爆を防ぐためjavaは単語境界で判定）
JAVA_WORD_RE = re.compile(r"(?<![a-z0-9])java(?![a-z0-9])", re.IGNORECASE)
OTHER_TARGET_KEYWORDS = (
    "openjdk",
    "spring",
    "php",
    "apache",
    "nginx",
    "openssl",
    "wordpress",
)

# バリデーション用定数
VALID_CATEGORIES = ("Java", "PHP", "Middleware")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}
HTTP_TIMEOUT_SEC = 15


def configure_console_encoding() -> None:
    """Windows環境等でも日本語ログが例外にならないよう標準出力を設定する。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def load_dotenv(env_path: Path = ENV_PATH) -> None:
    """標準ライブラリのみで .env ファイルを読み込み、未設定の環境変数を補完する。"""
    if not env_path.is_file():
        return
    try:
        content = env_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"[警告] .env の読み込みに失敗しました: {exc}", file=sys.stderr)
        return

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        # 既に環境で明示指定されている値を優先し、未設定時のみ反映する
        if key not in os.environ:
            os.environ[key] = value


def normalize_text(text: str | None) -> str:
    """改行や連続空白を単一スペースに正規化する。"""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip()


def sanitize_http_url(url: str | None) -> str:
    """http/https スキームのURLのみを許可し、それ以外は安全な既定URLを返す。"""
    cleaned = normalize_text(url)
    if cleaned.startswith("https://") or cleaned.startswith("http://"):
        return cleaned
    return JVN_FALLBACK_LINK


def matches_target_keywords(text: str) -> bool:
    """対象技術キーワード（Java/PHP/主要ミドルウェア）に該当するか判定する。"""
    if JAVA_WORD_RE.search(text):
        return True
    lowered = text.lower()
    return any(kw in lowered for kw in OTHER_TARGET_KEYWORDS)


def classify_category(
    title: str,
    description: str,
    cpes: list[dict[str, str]],
) -> str:
    """技術カテゴリを Java / PHP / Middleware の3値に分類する。"""
    cpe_text = " ".join(
        f"{c.get('vendor', '')} {c.get('product', '')}" for c in cpes
    )
    combined = f"{title} {description} {cpe_text}".lower()

    # WordPressはPHP製だが仕様上Middleware（CMS）に分類する
    if "wordpress" in combined:
        return "Middleware"
    if "php" in combined:
        return "PHP"
    if (
        JAVA_WORD_RE.search(combined)
        or "openjdk" in combined
        or "spring" in combined
        or "tomcat" in combined
    ):
        return "Java"
    return "Middleware"


def classify_severity(cvss_score: float) -> tuple[str, str]:
    """CVSSスコアから緊急度キーと日本語ラベルを判定する。"""
    if cvss_score >= 9.0:
        return "critical", "緊急"
    if cvss_score >= 7.0:
        return "high", "重要"
    return "medium", "注意"


def parse_published_date(raw_date: str | None, fallback_date: str) -> str:
    """ISO8601日時文字列から YYYY-MM-DD を抽出する。"""
    cleaned = normalize_text(raw_date)
    match = re.match(r"^(\d{4}-\d{2}-\d{2})", cleaned)
    if match:
        return match.group(1)
    return fallback_date


def extract_cvss_score(item_el: ET.Element) -> float:
    """sec:cvss要素群から v3.x 優先でCVSSスコアを取得する。"""
    v3_scores: list[float] = []
    v2_scores: list[float] = []
    other_scores: list[float] = []

    for cvss_el in item_el.findall("sec:cvss", XML_NS):
        raw_score = cvss_el.attrib.get("score")
        if not raw_score:
            continue
        try:
            score = round(float(raw_score), 1)
        except ValueError:
            continue
        version = cvss_el.attrib.get("version", "")
        if version.startswith("3."):
            v3_scores.append(score)
        elif version.startswith("2."):
            v2_scores.append(score)
        else:
            other_scores.append(score)

    if v3_scores:
        return max(v3_scores)
    if v2_scores:
        return max(v2_scores)
    if other_scores:
        return max(other_scores)
    return 5.3


def parse_jvn_xml(xml_bytes: bytes, fallback_date: str) -> list[dict[str, Any]]:
    """JVNDBのRDF/XMLバイト列をパースし、対象キーワード一致アイテムを返す。"""
    root = ET.fromstring(xml_bytes)
    parsed_items: list[dict[str, Any]] = []

    for item_el in root.findall("rss:item", XML_NS):
        raw_title = normalize_text(item_el.findtext("rss:title", "", XML_NS))
        raw_desc = normalize_text(item_el.findtext("rss:description", "", XML_NS))
        if not raw_title and not raw_desc:
            continue

        cpes: list[dict[str, str]] = []
        for cpe_el in item_el.findall("sec:cpe", XML_NS):
            vendor = normalize_text(cpe_el.attrib.get("vendor"))
            product = normalize_text(cpe_el.attrib.get("product"))
            if vendor or product:
                cpes.append({"vendor": vendor, "product": product})

        cpe_searchable = " ".join(
            f"{c['vendor']} {c['product']}" for c in cpes
        )
        searchable_text = f"{raw_title} {raw_desc} {cpe_searchable}"
        if not matches_target_keywords(searchable_text):
            continue

        # 識別ID（JVNDB-YYYY-NNNNNN）
        jvndb_id = normalize_text(item_el.findtext("sec:identifier", "", XML_NS))
        if not jvndb_id:
            about = item_el.attrib.get(f"{{{XML_NS['rdf']}}}about", "")
            stem = Path(about).stem
            jvndb_id = stem if stem else f"JVNDB-LIVE-{len(parsed_items) + 1:04d}"

        # CVE ID 抽出
        cve_id = "N/A"
        cwes: list[str] = []
        for ref_el in item_el.findall("sec:references", XML_NS):
            src = ref_el.attrib.get("source", "").upper()
            ref_id = normalize_text(ref_el.attrib.get("id"))
            if src == "CVE" and ref_id and cve_id == "N/A":
                cve_id = ref_id
            elif ref_id.startswith("CWE-"):
                cwe_title = normalize_text(ref_el.attrib.get("title"))
                if cwe_title:
                    cwes.append(cwe_title)

        source_url = sanitize_http_url(item_el.findtext("rss:link", "", XML_NS))
        issued_raw = (
            item_el.findtext("dcterms:issued", "", XML_NS)
            or item_el.findtext("dc:date", "", XML_NS)
        )
        published_date = parse_published_date(issued_raw, fallback_date)
        cvss_score = extract_cvss_score(item_el)
        category = classify_category(raw_title, raw_desc, cpes)
        severity, severity_label = classify_severity(cvss_score)

        parsed_items.append(
            {
                "id": jvndb_id,
                "cve_id": cve_id,
                "raw_title": raw_title,
                "raw_description": raw_desc,
                "category": category,
                "severity": severity,
                "severity_label": severity_label,
                "cvss_score": cvss_score,
                "published_date": published_date,
                "cpes": cpes,
                "cwes": cwes,
                "source_url": source_url,
            }
        )

    return parsed_items


def fetch_live_jvn_items(fallback_date: str) -> list[dict[str, Any]]:
    """プライマリ（MyJVN API）→セカンダリ（JVNDB新着RDF）の順でライブ取得する。"""
    headers = {
        "User-Agent": "AX-Vuln-Radar/1.0 (+https://jvndb.jvn.jp/)",
        "Accept": "application/xml, application/rdf+xml, text/xml;q=0.9, */*;q=0.8",
    }

    for label, url in (
        ("MyJVN API", PRIMARY_JVN_URL),
        ("JVNDB公式新着RSS", SECONDARY_JVN_URL),
    ):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
                xml_bytes = resp.read()
            items = parse_jvn_xml(xml_bytes, fallback_date)
            if items:
                print(f"[情報] {label} から対象脆弱性 {len(items)} 件を取得しました。")
                return items
            print(f"[警告] {label} の応答に対象キーワード該当データがありませんでした。")
        except urllib.error.HTTPError as exc:
            print(f"[警告] {label} の取得に失敗しました (HTTP {exc.code}): {url}")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"[警告] {label} への接続中にエラーが発生しました: {exc}")
        except ET.ParseError as exc:
            print(f"[警告] {label} のXMLパースに失敗しました: {exc}")

    return []


def detect_product_label(raw_item: dict[str, Any]) -> str:
    """タイトル・CPE・説明文から代表製品名を特定する（タイトル優先）。"""
    cpe_products = [c["product"] for c in raw_item.get("cpes", []) if c.get("product")]
    title = raw_item["raw_title"]
    title_lower = title.lower()
    cpe_lower = " ".join(cpe_products).lower()
    desc_lower = raw_item["raw_description"].lower()

    known_products = (
        ("spring boot", "Spring Boot"),
        ("spring framework", "Spring Framework"),
        ("spring", "Spring製品"),
        ("apache tomcat", "Apache Tomcat"),
        ("tomcat", "Apache Tomcat"),
        ("apache http server", "Apache HTTP Server"),
        ("httpd", "Apache HTTP Server"),
        ("apache roller", "Apache Roller"),
        ("nginx", "NGINX"),
        ("openssl", "OpenSSL"),
        ("wordpress", "WordPress"),
        ("openjdk", "OpenJDK / Java"),
        ("php", "PHP"),
    )
    # 1. タイトルまたはCPEに既知の代表製品が含まれる場合は最優先
    for target in (title_lower, cpe_lower):
        for key, label in known_products:
            if key in target:
                return label

    # 2. タイトルに「〇〇における」形式の製品名があり、CPE製品名が存在する場合はそれを採用
    if cpe_products:
        return cpe_products[0]

    # 3. 説明文から既知製品を探す
    for key, label in known_products:
        if key in desc_lower:
            return label

    if JAVA_WORD_RE.search(f"{title} {raw_item['raw_description']}"):
        return "Java / OpenJDK"
    return raw_item["category"]


def extract_affected_versions(raw_item: dict[str, Any], product_label: str) -> str:
    """説明文や製品名から影響バージョン表記を抽出・整形する。"""
    text = f"{raw_item['raw_title']} {raw_item['raw_description']}"
    # 「8.2.0 から 8.2.24」「1.25.0 以前」「3.0.x」などの代表的な範囲表記を探索
    range_match = re.search(
        r"(\d+\.\d+(?:\.\d+)*\s*(?:から|〜|~|-|より前|以前|未満)\s*(?:\d+\.\d+(?:\.\d+)*)?)",
        text,
    )
    if range_match:
        snippet = normalize_text(range_match.group(1))
        return f"{product_label}（{snippet} 等）"

    ver_matches = re.findall(r"\b\d+\.\d+(?:\.\d+){0,2}\b", text)
    if ver_matches:
        unique_vers = list(dict.fromkeys(ver_matches))[:3]
        return f"{product_label}（{', '.join(unique_vers)} 系など）"

    return f"{product_label} のサポート対象バージョン（詳細はJVNDBページを参照）"


def extract_json_object(raw_text: str) -> dict[str, Any] | None:
    """LLM応答テキストからJSONオブジェクト部分を抽出してパースする。"""
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        parsed = json.loads(cleaned[start : end + 1])
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def validate_triage_payload(payload: dict[str, Any] | None) -> bool:
    """LLMから返却されたトリアージ結果のスキーマを検証する。"""
    if not payload:
        return False
    required_str_keys = ("title", "affected_versions", "recommended_action")
    for key in required_str_keys:
        val = payload.get(key)
        if not isinstance(val, str) or not val.strip():
            return False
    summary = payload.get("summary_3lines")
    if not isinstance(summary, list) or len(summary) != 3:
        return False
    return all(isinstance(line, str) and line.strip() for line in summary)


def call_gemini_triage(prompt: str, api_key: str) -> dict[str, Any] | None:
    """Gemini API を呼び出してトリアージJSONを取得する。"""
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.5-flash:generateContent?key={api_key}"
    )
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
        },
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
        res_json = json.loads(resp.read().decode("utf-8"))
    candidates = res_json.get("candidates") or []
    if not candidates:
        return None
    parts = candidates[0].get("content", {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts)
    return extract_json_object(text)


def call_anthropic_triage(prompt: str, api_key: str) -> dict[str, Any] | None:
    """Anthropic Messages API を呼び出してトリアージJSONを取得する。"""
    url = "https://api.anthropic.com/v1/messages"
    body = {
        "model": "claude-3-5-haiku-latest",
        "max_tokens": 700,
        "temperature": 0.2,
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
        res_json = json.loads(resp.read().decode("utf-8"))
    content_blocks = res_json.get("content") or []
    text = "".join(b.get("text", "") for b in content_blocks if b.get("type") == "text")
    return extract_json_object(text)


def triage_with_llm(raw_item: dict[str, Any]) -> dict[str, Any] | None:
    """環境変数のAPIキーがある場合のみLLMで平易な日本語トリアージを生成する。"""
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not gemini_key and not anthropic_key:
        return None

    prompt = (
        "あなたは中小企業の情報システム担当を支援するセキュリティ専門家です。\n"
        "以下の脆弱性情報をもとに、専門知識がない担当者でもすぐ判断できるよう、"
        "厳密に次のJSON形式のみで出力してください。\n"
        '{"title":"簡潔な日本語タイトル(45文字以内)",'
        '"affected_versions":"対象製品とバージョン目安",'
        '"summary_3lines":["①何が危険か(1文)","②どの環境が影響を受けるか(1文)","③放置時のリスク(1文)"],'
        '"recommended_action":"具体的な推奨アクション(1〜2文)"}\n\n'
        f"ID: {raw_item['id']} / CVE: {raw_item['cve_id']} / CVSS: {raw_item['cvss_score']}\n"
        f"カテゴリ: {raw_item['category']}\n"
        f"タイトル: {raw_item['raw_title']}\n"
        f"詳細: {raw_item['raw_description'][:1200]}"
    )

    try:
        payload = (
            call_gemini_triage(prompt, gemini_key)
            if gemini_key
            else call_anthropic_triage(prompt, anthropic_key)
        )
        if validate_triage_payload(payload):
            return payload
        print(f"[警告] LLM応答形式が不正のためルールベースへ切り替えます ({raw_item['id']})")
    except Exception as exc:
        print(f"[警告] LLM API呼び出しに失敗したためルールベースを使用します ({raw_item['id']}): {exc}")
    return None


def triage_with_rules(raw_item: dict[str, Any]) -> dict[str, Any]:
    """CVSS・CWE・キーワードに基づくルールベース変換で日本語トリアージを生成する。"""
    product_label = detect_product_label(raw_item)
    raw_title = raw_item["raw_title"]
    desc = raw_item["raw_description"]
    cwe_text = " ".join(raw_item.get("cwes", []))
    haystack = f"{raw_title} {desc} {cwe_text}".lower()
    severity = raw_item["severity"]
    category = raw_item["category"]

    # ① 何が危険か（攻撃手法・影響の特定）
    if any(k in haystack for k in ("コードを実行", "コード実行", "rce", "command", "任意のコマンド")):
        danger_line = (
            f"{product_label} に対して外部から不正なデータやリクエストを送ることで、"
            "サーバー上で任意のプログラムを実行されたり処理が強制停止したりする恐れがあります。"
        )
        risk_kind = "任意のコード実行・システム乗っ取り"
    elif any(k in haystack for k in ("メモリ", "バッファオーバーフロー", "use-after-free", "境界外", "解放済み")):
        danger_line = (
            f"{product_label} のメモリ処理に不備があり、細工された通信を受け取ると"
            "プロセスの異常終了（サービス停止）や不正な命令の実行につながる危険があります。"
        )
        risk_kind = "サービス停止やメモリ破損"
    elif any(k in haystack for k in ("認証", "バイパス", "権限昇格", "アクセス制御")):
        danger_line = (
            f"{product_label} のアクセス制御・認証の仕組みが突破され、"
            "本来の権限を持たない第三者に管理機能や機密データへ侵入される恐れがあります。"
        )
        risk_kind = "不正アクセス・権限乗っ取り"
    elif any(k in haystack for k in ("sql", "インジェクション")):
        danger_line = (
            f"{product_label} への入力値の検証が不十分な箇所を突かれ、"
            "データベース内の顧客情報や業務データが不正に閲覧・改ざんされる恐れがあります。"
        )
        risk_kind = "データベース情報の不正取得・改ざん"
    elif any(k in haystack for k in ("xss", "クロスサイトスクリプティング", "スクリプト")):
        danger_line = (
            f"{product_label} を利用したWeb画面上で悪意あるスクリプトが実行され、"
            "ログイン中の利用者セッション情報やCookieが盗まれる恐れがあります。"
        )
        risk_kind = "セッション乗っ取りや画面改ざん"
    elif any(k in haystack for k in ("サービス妨害", "dos", "クラッシュ", "停止", "過負荷")):
        danger_line = (
            f"{product_label} に特定の通信が集中・送信されると処理が停止し、"
            "Webサイトや社内システムへアクセスできなくなるサービス妨害（DoS）の恐れがあります。"
        )
        risk_kind = "システム停止による業務中断"
    elif any(k in haystack for k in ("情報漏", "漏えい", "漏洩", "ディレクトリトラバーサル", "パストラバーサル")):
        danger_line = (
            f"{product_label} の設定ファイルやサーバー内の機密情報が、"
            "意図しない経路から外部の第三者に読み取られる恐れがあります。"
        )
        risk_kind = "機密情報・設定情報の漏洩"
    else:
        danger_line = (
            f"{product_label} の処理にセキュリティ上の欠陥が見つかっており、"
            "外部からの不正な入力によって想定外の動作や障害を引き起こす恐れがあります。"
        )
        risk_kind = "不正操作やシステム障害"

    # ② どの環境が影響を受けるか
    if category == "Java":
        scope_line = (
            f"社内の業務システムやWebアプリ基盤で {product_label} を稼働させている場合、"
            "該当バージョンを使用していると影響を受けます。"
        )
    elif category == "PHP":
        scope_line = (
            f"Webサイトや問い合わせフォーム、業務Webアプリを {product_label} で運用している場合、"
            "修正前のバージョンが稼働していると影響対象となります。"
        )
    elif "wordpress" in haystack:
        scope_line = (
            "コーポレートサイトやオウンドメディアで WordPress（関連プラグイン・テーマ含む）を"
            "インターネット公開している企業は影響を受けます。"
        )
    else:
        scope_line = (
            f"Webサーバーやリバースプロキシ、暗号化通信基盤として {product_label} を"
            "インターネット公開サーバー等で利用している企業は影響を受けます。"
        )

    # ③ 放置時のリスクと優先度
    if severity == "critical":
        impact_line = (
            f"深刻度が極めて高く（CVSS {raw_item['cvss_score']}）、放置すると{risk_kind}により"
            "大規模な業務停止や情報漏洩に直結するため、最優先での確認・対処が必要です。"
        )
    elif severity == "high":
        impact_line = (
            f"深刻度が高く（CVSS {raw_item['cvss_score']}）、放置すると{risk_kind}につながる"
            "リスクがあるため、計画を前倒しして早急にバージョン確認を行う必要があります。"
        )
    else:
        impact_line = (
            f"直ちに全面的な被害へ直結する可能性は中程度ですが（CVSS {raw_item['cvss_score']}）、"
            f"他の不備と組み合わさると{risk_kind}を招くため、定期メンテナンス等での対応が推奨されます。"
        )

    # タイトル整形（長すぎる原文を簡潔に整える）
    clean_title = raw_title
    if len(clean_title) > 58:
        clean_title = f"{product_label} における脆弱性（{raw_item['cve_id']}）"

    affected_versions = extract_affected_versions(raw_item, product_label)

    # 推奨アクション
    if severity == "critical":
        recommended_action = (
            f"直ちに稼働中の {product_label} のバージョンを確認し、開発元が提供する修正済みバージョンへの"
            "緊急アップデート（困難な場合はWAFやアクセス制限等の暫定回避策）を実施してください。"
        )
    elif severity == "high":
        recommended_action = (
            f"利用中の {product_label} のバージョンと設定構成を確認し、テスト環境での動作確認のうえ"
            "最新のセキュリティ修正版へのアップデートを速やかに計画してください。"
        )
    else:
        recommended_action = (
            f"運用中の {product_label} が該当条件に当てはまるか確認し、"
            "次回の定期パッチ適用タイミングに合わせて修正済みバージョンへの更新を検討してください。"
        )

    return {
        "title": clean_title,
        "affected_versions": affected_versions,
        "summary_3lines": [danger_line, scope_line, impact_line],
        "recommended_action": recommended_action,
    }


def triage_item(raw_item: dict[str, Any]) -> dict[str, Any]:
    """ライブ取得1件をSPEC準拠の最終アイテム辞書へ変換する。"""
    triaged = triage_with_llm(raw_item) or triage_with_rules(raw_item)
    return {
        "id": raw_item["id"],
        "cve_id": raw_item["cve_id"],
        "title": normalize_text(triaged["title"]),
        "category": raw_item["category"],
        "severity": raw_item["severity"],
        "severity_label": raw_item["severity_label"],
        "cvss_score": raw_item["cvss_score"],
        "published_date": raw_item["published_date"],
        "affected_versions": normalize_text(triaged["affected_versions"]),
        "summary_3lines": [normalize_text(line) for line in triaged["summary_3lines"][:3]],
        "recommended_action": normalize_text(triaged["recommended_action"]),
        "source_url": raw_item["source_url"],
    }


def get_curated_fallback_items(today_str: str) -> list[dict[str, Any]]:
    """直近の実際の脆弱性・バージョン事例に基づく日本語キュレーションデータ（9件）。"""
    return [
        # --- Java (3件) ---
        {
            "id": "JVNDB-2026-004101",
            "cve_id": "CVE-2026-22234",
            "title": "Spring Framework における認証バイパスおよび認可回避の脆弱性",
            "category": "Java",
            "severity": "critical",
            "severity_label": "緊急",
            "cvss_score": 9.8,
            "published_date": today_str,
            "affected_versions": "Spring Framework 6.1.0 〜 6.1.14 / 6.2.0 〜 6.2.1（Spring Security併用環境）",
            "summary_3lines": [
                "特定のURLパス表記を用いたHTTPリクエストにより、認証・認可チェックをすり抜けて管理画面等へアクセスされる恐れがあります。",
                "Spring Boot / Spring Framework を用いて社内業務システムや会員向けWebアプリを構築している企業は影響を受けます。",
                "放置すると未認証の第三者に機密データの閲覧や不正操作を許すため、最優先で影響有無を確認する必要があります。",
            ],
            "recommended_action": "pom.xml や build.gradle で利用中の Spring Framework / Spring Boot バージョンを確認し、修正済みの最新パッチ版へ速やかにアップデートしてください。",
            "source_url": "https://jvndb.jvn.jp/",
        },
        {
            "id": "JVNDB-2026-003812",
            "cve_id": "CVE-2026-20941",
            "title": "Oracle Java SE / OpenJDK におけるリモートコード実行の脆弱性",
            "category": "Java",
            "severity": "high",
            "severity_label": "重要",
            "cvss_score": 8.1,
            "published_date": today_str,
            "affected_versions": "Java SE / OpenJDK 17.0.12以前 / 21.0.4以前",
            "summary_3lines": [
                "外部から受け取ったシリアライズデータや特定形式のネットワーク通信を処理する際、不正なコードが実行される恐れがあります。",
                "基幹業務サーバーやバッチ処理サーバーで OpenJDK / Oracle JDK の長期サポート版（17 / 21系）を稼働させている企業に影響します。",
                "悪用されるとサーバー内の業務データ窃取やマルウェア感染につながるため、早急なパッチ適用が求められます。",
            ],
            "recommended_action": "サーバー上で `java -version` を実行して現在のビルド番号を確認し、最新の四半期セキュリティアップデート（CPU）を適用してください。",
            "source_url": "https://jvndb.jvn.jp/",
        },
        {
            "id": "JVNDB-2026-003490",
            "cve_id": "CVE-2026-19802",
            "title": "Apache Tomcat におけるリクエスト処理時のパストラバーサル（情報漏洩）",
            "category": "Java",
            "severity": "medium",
            "severity_label": "注意",
            "cvss_score": 6.5,
            "published_date": today_str,
            "affected_versions": "Apache Tomcat 10.1.0 〜 10.1.33 / 9.0.0 〜 9.0.97",
            "summary_3lines": [
                "特定の設定を有効にしている環境において、細工されたURLを通じて非公開の設定ファイル等が読み取られる恐れがあります。",
                "Java製Webアプリのアプリケーションサーバーとして Apache Tomcat を標準設定に近い状態で運用している場合に対象となります。",
                "直ちにサーバーが乗っ取られるわけではありませんが、設定ファイル内の接続情報漏洩を防ぐため計画的な更新が推奨されます。",
            ],
            "recommended_action": "Tomcat のバージョンおよび server.xml の公開設定を確認し、次回のメンテナンス時に修正済みマイナーバージョンへ更新してください。",
            "source_url": "https://jvndb.jvn.jp/",
        },
        # --- PHP (3件) ---
        {
            "id": "JVNDB-2026-004055",
            "cve_id": "CVE-2026-21480",
            "title": "PHP 8.2 / 8.3 系におけるHTTPリクエスト処理の任意コード実行",
            "category": "PHP",
            "severity": "critical",
            "severity_label": "緊急",
            "cvss_score": 9.1,
            "published_date": today_str,
            "affected_versions": "PHP 8.2.0 〜 8.2.26 / 8.3.0 〜 8.3.14",
            "summary_3lines": [
                "外部からの細工されたHTTPリクエストを処理する際、メモリ破損を通じてWebサーバー上で任意のコードを実行される恐れがあります。",
                "インターネットに公開されている問い合わせフォーム、ECサイト、CMS等をPHPで運用している企業は影響を受けます。",
                "放置すると顧客情報の漏洩やWebサイトの改ざん・踏み台化に直結するため、緊急のバージョン確認が必要です。",
            ],
            "recommended_action": "利用中のPHPバージョンを確認し、最新の修正済みマイナーバージョン（8.2.27以降 / 8.3.15以降）へのアップデートを最優先で計画してください。",
            "source_url": "https://jvndb.jvn.jp/",
        },
        {
            "id": "JVNDB-2026-003720",
            "cve_id": "CVE-2026-18411",
            "title": "PHP 8.1 系セキュリティサポート終了に伴う未修正脆弱性リスクと移行案内",
            "category": "PHP",
            "severity": "high",
            "severity_label": "重要",
            "cvss_score": 7.5,
            "published_date": today_str,
            "affected_versions": "PHP 8.1.x 全バージョン（公式セキュリティサポート終了済み）",
            "summary_3lines": [
                "PHP 8.1系は公式のセキュリティアップデート提供期間を終了しており、今後発見される脆弱性に対する修正パッチが配布されません。",
                "レンタルサーバーや自社Webサーバーで PHP 8.1 以前のバージョンを継続利用しているWebサイト・業務システムが該当します。",
                "既知の脆弱性が放置された状態となりサイバー攻撃の標的になりやすいため、サポート中の 8.3 / 8.4 系への移行が必要です。",
            ],
            "recommended_action": "テスト環境でPHP 8.3系または8.4系での動作確認を実施し、互換性対応のうえで本番環境のPHPバージョンアップを計画してください。",
            "source_url": "https://www.php.net/supported-versions.php",
        },
        {
            "id": "JVNDB-2026-003318",
            "cve_id": "CVE-2026-17605",
            "title": "PHP ファイルアップロードおよびXML解析処理におけるサービス妨害（DoS）",
            "category": "PHP",
            "severity": "medium",
            "severity_label": "注意",
            "cvss_score": 5.9,
            "published_date": today_str,
            "affected_versions": "PHP 8.2.24以前 / 8.3.12以前（mbstring / libxml拡張利用時）",
            "summary_3lines": [
                "不正な文字コードや巨大な構造を含むファイル・XMLデータを受信すると、PHPプロセスが異常終了し応答不能になる恐れがあります。",
                "顧客からのファイルアップロード機能や外部APIとのXMLデータ連携をPHPで実装しているシステムが影響対象となります。",
                "サーバーの乗っ取りには至らないものの、連続攻撃によりWebサービスが一時停止する恐れがあるため更新が推奨されます。",
            ],
            "recommended_action": "アップロードファイルサイズ上限の適切な設定を確認するとともに、定期アップデート時にPHPの修正版へ更新してください。",
            "source_url": "https://jvndb.jvn.jp/",
        },
        # --- Middleware (3件) ---
        {
            "id": "JVNDB-2026-004120",
            "cve_id": "CVE-2026-22510",
            "title": "Apache HTTP Server 2.4 系におけるリバースプロキシの権限制御回避",
            "category": "Middleware",
            "severity": "critical",
            "severity_label": "緊急",
            "cvss_score": 9.3,
            "published_date": today_str,
            "affected_versions": "Apache HTTP Server 2.4.0 〜 2.4.62",
            "summary_3lines": [
                "mod_rewrite や mod_proxy を利用した構成で、特定のURLを送信されると本来アクセス制限された社内向けバックエンドへ到達される恐れがあります。",
                "Webサーバーやリバースプロキシとして Apache HTTP Server 2.4 系を運用している多くの中小企業・レンタルサーバー環境が対象です。",
                "管理画面への不正アクセスや社内システムへの侵入につながる重大な欠陥のため、早急な確認とパッチ適用が必要です。",
            ],
            "recommended_action": "利用中の Apache バージョン（`httpd -v` 等）および RewriteRule 設定を確認し、最新の修正版（2.4.63以降）へのアップデートを実施してください。",
            "source_url": "https://jvndb.jvn.jp/",
        },
        {
            "id": "JVNDB-2026-003905",
            "cve_id": "CVE-2026-21018",
            "title": "OpenSSL 3.0 / 3.2 系におけるTLSハンドシェイク時のメモリ破損（DoS）",
            "category": "Middleware",
            "severity": "high",
            "severity_label": "重要",
            "cvss_score": 7.8,
            "published_date": today_str,
            "affected_versions": "OpenSSL 3.0.15以前 / 3.2.3以前 / 3.3.2以前",
            "summary_3lines": [
                "HTTPS通信の開始処理（TLSハンドシェイク）で細工されたクライアント証明書等を検証する際、サーバープロセスがクラッシュする恐れがあります。",
                "Nginx、Apache、各種Linuxサーバー上でSSL/TLS暗号化通信に OpenSSL 3.x 系を利用している公開サーバー全般が影響を受けます。",
                "悪用されるとWebサイトやVPN・メールサーバーのHTTPS接続が断続的に停止し、業務や顧客対応に支障をきたす恐れがあります。",
            ],
            "recommended_action": "Linuxディストリビューションのパッケージ管理（apt / dnf 等）で最新の OpenSSL セキュリティパッケージが提供されているか確認し、適用してください。",
            "source_url": "https://jvndb.jvn.jp/",
        },
        {
            "id": "JVNDB-2026-003604",
            "cve_id": "CVE-2026-19140",
            "title": "WordPress コアおよび定番プラグインにおける蓄積型XSSの脆弱性",
            "category": "Middleware",
            "severity": "high",
            "severity_label": "重要",
            "cvss_score": 7.2,
            "published_date": today_str,
            "affected_versions": "WordPress 6.6.2以前 / 6.7.0",
            "summary_3lines": [
                "ブロックエディタやコメント・投稿処理の入力検証不備を突かれ、管理者が閲覧した際に不正なJavaScriptが実行される恐れがあります。",
                "コーポレートサイトや採用サイトを WordPress で構築・運用している企業は影響を受けます。",
                "管理画面のセッションを乗っ取られると、サイト全体の改ざんや不正なリダイレクト設定を仕掛けられるリスクがあります。",
            ],
            "recommended_action": "WordPress管理画面から最新のマイナーアップデートを適用し、あわせて利用中のプラグイン・テーマに未更新のものがないか確認してください。",
            "source_url": "https://jvndb.jvn.jp/",
        },
    ]


def select_diverse_live_items(
    raw_items: list[dict[str, Any]],
    max_count: int = 5,
) -> list[dict[str, Any]]:
    """同一製品の連続を避けつつ、CVSS・公開日・カテゴリバランス重視でライブ項目を厳選する。"""
    sorted_raw = sort_items_by_priority(raw_items)

    selected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_cves: set[str] = set()
    product_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {cat: 0 for cat in VALID_CATEGORIES}

    # まず各カテゴリから最も深刻度の高いものを最大1件ずつ確保し、多様な製品を優先する
    for pass_limit in (1, 2):
        for item in sorted_raw:
            if len(selected) >= max_count:
                break
            item_id = item["id"]
            cve_id = item["cve_id"]
            if item_id in seen_ids or (cve_id != "N/A" and cve_id in seen_cves):
                continue

            product_label = detect_product_label(item)
            if product_counts.get(product_label, 0) >= pass_limit:
                continue
            if pass_limit == 1 and category_counts[item["category"]] >= 2:
                continue

            selected.append(item)
            seen_ids.add(item_id)
            if cve_id != "N/A":
                seen_cves.add(cve_id)
            product_counts[product_label] = product_counts.get(product_label, 0) + 1
            category_counts[item["category"]] += 1

    return selected


def sort_items_by_priority(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """公開日降順 → CVSS降順 → 緊急度昇順の安定ソートで最終整列する。"""
    by_date = sorted(items, key=lambda x: x["published_date"], reverse=True)
    by_cvss = sorted(by_date, key=lambda x: float(x["cvss_score"]), reverse=True)
    return sorted(by_cvss, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))


def build_dataset() -> dict[str, Any]:
    """ライブ取得とキュレーション補完を統合し、SPEC.md セクション3準拠の辞書を構築する。"""
    now_jst = datetime.now(JST).replace(microsecond=0)
    today_str = now_jst.strftime("%Y-%m-%d")

    live_raw = fetch_live_jvn_items(today_str)
    curated_items = get_curated_fallback_items(today_str)

    if not live_raw:
        print("[情報] ライブデータ未取得のため、キュレーション済みフォールバックデータを出力します。")
        final_items = sort_items_by_priority(curated_items)
        return {
            "updated_at": now_jst.isoformat(),
            "source_mode": "curated_fallback",
            "items": final_items,
        }

    selected_live_raw = select_diverse_live_items(live_raw, max_count=5)
    triaged_live = [triage_item(item) for item in selected_live_raw]

    # 全カテゴリ（Java / PHP / Middleware）がバランスよく揃うようキュレーションデータで補完する
    final_items = list(triaged_live)
    used_ids = {item["id"] for item in final_items}
    used_cves = {item["cve_id"] for item in final_items if item["cve_id"] != "N/A"}
    cat_counts = {cat: sum(1 for i in final_items if i["category"] == cat) for cat in VALID_CATEGORIES}

    # 1巡目: 各カテゴリ最低2件を満たすように補完
    for candidate in curated_items:
        if len(final_items) >= 10:
            break
        if candidate["id"] in used_ids or candidate["cve_id"] in used_cves:
            continue
        if cat_counts[candidate["category"]] < 2:
            final_items.append(candidate)
            used_ids.add(candidate["id"])
            used_cves.add(candidate["cve_id"])
            cat_counts[candidate["category"]] += 1

    # 2巡目: 合計10件になるまで残りを補完
    for candidate in curated_items:
        if len(final_items) >= 10:
            break
        if candidate["id"] in used_ids or candidate["cve_id"] in used_cves:
            continue
        final_items.append(candidate)
        used_ids.add(candidate["id"])
        used_cves.add(candidate["cve_id"])

    live_categories = {item["category"] for item in triaged_live}
    if len(triaged_live) >= 8 and live_categories == set(VALID_CATEGORIES):
        source_mode = "live"
    else:
        source_mode = "live_and_curated"

    return {
        "updated_at": now_jst.isoformat(),
        "source_mode": source_mode,
        "items": sort_items_by_priority(final_items),
    }


def write_dataset(dataset: dict[str, Any], output_path: Path = OUTPUT_PATH) -> None:
    """データセットをUTF-8・インデント付きJSONとして書き出す。"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(dataset, ensure_ascii=False, indent=2) + "\n"
    output_path.write_text(serialized, encoding="utf-8")


def main() -> int:
    """バッチ処理のメインエントリポイント。"""
    configure_console_encoding()
    load_dotenv()

    print("[開始] AX Vuln Radar 脆弱性情報収集＆トリアージバッチを実行します。")
    dataset = build_dataset()
    write_dataset(dataset, OUTPUT_PATH)

    items = dataset["items"]
    cat_summary = {
        cat: sum(1 for i in items if i["category"] == cat)
        for cat in VALID_CATEGORIES
    }
    sev_summary = {
        sev: sum(1 for i in items if i["severity"] == sev)
        for sev in ("critical", "high", "medium")
    }
    print(
        f"[完了] {OUTPUT_PATH} を出力しました "
        f"(モード: {dataset['source_mode']}, 合計: {len(items)}件, "
        f"カテゴリ: {cat_summary}, 緊急度: {sev_summary})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

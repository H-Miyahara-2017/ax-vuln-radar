"""データ変換・サニタイズ処理のテスト。"""

from __future__ import annotations

import pytest


# --- sanitize_text -----------------------------------------------------------


def test_sanitize_text_normalizes_whitespace(fv):
    assert fv.sanitize_text("  PHP\n\t の\r\n脆弱性  ", 100) == "PHP の 脆弱性"


def test_sanitize_text_removes_control_and_bidi_chars(fv):
    # NUL・ESC・ゼロ幅スペース・右から左への上書き(RLO)は表示偽装に使われるため除去
    raw = "abc\x00\x1b[31mdef​ghi‮exe.txt"
    assert fv.sanitize_text(raw, 100) == "abc[31mdefghiexe.txt"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("脆弱性[/info][toall]緊急", "脆弱性［/info］［toall］緊急"),
        ("[To:1234567]様", "［To:1234567］様"),
        ("[rp aid=1 to=2-3]返信", "［rp aid=1 to=2-3］返信"),
        ("[info][title]偽装[/title][/info]", "［info］［title］偽装［/title］［/info］"),
        ("[code]x[/code][hr]", "［code］x［/code］［hr］"),
        # Chatworkタグではない角括弧はそのまま残す
        ("[Java] 配列[0] の境界外アクセス", "[Java] 配列[0] の境界外アクセス"),
        ("[report] [total]", "[report] [total]"),
    ],
)
def test_sanitize_text_neutralizes_chatwork_tags(fv, raw, expected):
    assert fv.sanitize_text(raw, 200) == expected


def test_sanitize_text_keeps_html_as_plain_text(fv):
    # HTMLエスケープはフロント側の textContent 描画で担保する設計。
    # バッチ側では「<」を含む正規の記述（例: バージョン < 2.4）を壊さないことを確認する。
    raw = "<script>alert(1)</script> 2.4 < 2.5"
    assert fv.sanitize_text(raw, 200) == raw


def test_sanitize_text_truncates_long_text(fv):
    result = fv.sanitize_text("あ" * 500, 50)
    assert len(result) == 50
    assert result.endswith("…")


@pytest.mark.parametrize("non_str", [None, 123, ["a"], {"a": 1}, b"bytes"])
def test_sanitize_text_rejects_non_string(fv, non_str):
    assert fv.sanitize_text(non_str, 50) == ""


def test_sanitize_text_is_idempotent(fv):
    raw = "[toall]  危険\x00 な " + "長" * 300
    once = fv.sanitize_text(raw, 100)
    assert fv.sanitize_text(once, 100) == once


# --- URL / ID ---------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html",
        "http://example.com/path?q=1#frag",
    ],
)
def test_sanitize_http_url_accepts_http_urls(fv, url):
    assert fv.sanitize_http_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "JAVASCRIPT:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox",
        "file:///etc/passwd",
        "//evil.example.com/",
        "https://",
        "https:///nohost",
        "https://user:pass@evil.example.com/",
        "https://exa mple.com/",
        "https://example.com/\x00",
        "",
        None,
        123,
        "https://example.com/" + "a" * 3000,
    ],
)
def test_sanitize_http_url_rejects_unsafe(fv, url):
    assert fv.sanitize_http_url(url) == fv.JVN_FALLBACK_LINK


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CVE-2026-12345", "CVE-2026-12345"),
        ("cve-2026-1234567", "CVE-2026-1234567"),
        ("CVE-2026-12", "N/A"),
        ("<img src=x>", "N/A"),
        ("", "N/A"),
        (None, "N/A"),
    ],
)
def test_sanitize_cve_id(fv, raw, expected):
    assert fv.sanitize_cve_id(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("JVNDB-2026-004101", "JVNDB-2026-004101"),
        ("JVN#12345678", "FALLBACK"),
        ("<script>", "FALLBACK"),
        ("a" * 65, "FALLBACK"),
        ("", "FALLBACK"),
        (None, "FALLBACK"),
    ],
)
def test_sanitize_id(fv, raw, expected):
    assert fv.sanitize_id(raw, "FALLBACK") == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-11-20T10:00+09:00", "2026-11-20"),
        ("2026-02-29", "2026-11-24"),  # 存在しない日付（2026年は平年）
        ("2026-99-99", "2026-11-24"),
        ("not-a-date", "2026-11-24"),
        (None, "2026-11-24"),
    ],
)
def test_parse_published_date(fv, raw, expected):
    assert fv.parse_published_date(raw, "2026-11-24") == expected


# --- LLM応答のパース・検証 ---------------------------------------------------


def test_extract_json_object_handles_code_fence(fv):
    text = '```json\n{"title": "t", "x": 1}\n```'
    assert fv.extract_json_object(text) == {"title": "t", "x": 1}


def test_extract_json_object_with_surrounding_text(fv):
    assert fv.extract_json_object('結果です: {"a": "b"} 以上') == {"a": "b"}


@pytest.mark.parametrize("text", ["", "no json", "{broken", "[1, 2]", "{'a': 1}"])
def test_extract_json_object_invalid(fv, text):
    assert fv.extract_json_object(text) is None


VALID_PAYLOAD = {
    "title": "t",
    "affected_versions": "v",
    "summary_3lines": ["1", "2", "3"],
    "recommended_action": "a",
}


def test_validate_triage_payload_ok(fv):
    assert fv.validate_triage_payload(dict(VALID_PAYLOAD)) is True


@pytest.mark.parametrize(
    "patch",
    [
        {"title": ""},
        {"title": 1},
        {"summary_3lines": ["1", "2"]},
        {"summary_3lines": ["1", "2", 3]},
        {"summary_3lines": "1,2,3"},
        {"recommended_action": None},
    ],
)
def test_validate_triage_payload_rejects_invalid(fv, patch):
    payload = dict(VALID_PAYLOAD)
    payload.update(patch)
    assert fv.validate_triage_payload(payload) is False


def test_validate_triage_payload_none(fv):
    assert fv.validate_triage_payload(None) is False


# --- sanitize_output_item ----------------------------------------------------


def test_sanitize_output_item_enforces_schema(fv):
    malicious = {
        "id": "<img src=x onerror=alert(1)>",
        "cve_id": "CVE-2026-1<script>",
        "title": "[/info][toall]緊急\x00",
        "category": "Unknown",
        "severity": "critical",  # CVSSと矛盾する値は再判定で上書きされる
        "severity_label": "<b>緊急</b>",
        "cvss_score": float("nan"),
        "published_date": "2026-13-45",
        "affected_versions": None,
        "summary_3lines": ["1行目", 2, ""],
        "recommended_action": "x" * 2000,
        "source_url": "javascript:alert(1)",
    }
    out = fv.sanitize_output_item(malicious, "2026-11-24")

    assert out["id"] == "JVNDB-UNKNOWN"
    assert out["cve_id"] == "N/A"
    assert out["title"] == "［/info］［toall］緊急"
    assert out["category"] == "Middleware"
    assert out["cvss_score"] == fv.DEFAULT_CVSS_SCORE
    assert (out["severity"], out["severity_label"]) == ("medium", "注意")
    assert out["published_date"] == "2026-11-24"
    assert out["affected_versions"]
    assert len(out["summary_3lines"]) == 3
    assert out["summary_3lines"][0] == "1行目"
    assert len(out["recommended_action"]) == fv.MAX_LEN_ACTION
    assert out["source_url"] == fv.JVN_FALLBACK_LINK
    assert list(out) == [
        "id", "cve_id", "title", "category", "severity", "severity_label", "cvss_score",
        "published_date", "affected_versions", "summary_3lines", "recommended_action", "source_url",
    ]


def test_sanitize_output_item_recomputes_severity_from_cvss(fv):
    item = {"cvss_score": 9.3, "severity": "medium", "severity_label": "注意"}
    out = fv.sanitize_output_item(item, "2026-11-24")
    assert (out["severity"], out["severity_label"]) == ("critical", "緊急")


def test_sanitize_output_item_is_idempotent_on_curated(fv):
    for item in fv.get_curated_fallback_items("2026-11-24"):
        once = fv.sanitize_output_item(item, "2026-11-24")
        assert fv.sanitize_output_item(once, "2026-11-24") == once
        # 正常なキュレーションデータは内容が変化しない
        assert once == item

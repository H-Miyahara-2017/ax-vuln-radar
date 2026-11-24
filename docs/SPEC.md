# SPEC.md - AX Vuln Radar システム要件定義・設計仕様書

## 1. システム概要
- **名称:** AX Vuln Radar（中小企業向けセキュリティ・バージョン情報自動収集＆トリアージダッシュボード）
- **目的:** 専任の情シス担当が不在の中小企業およびBPO運用チーム向けに、Java・PHP・Webミドルウェア等の最新脆弱性・バージョンアップ情報を自動収集し、AIによる平易な解説とChatwork報告用テンプレートを1画面で提供する。

## 2. データ収集・加工バッチ仕様 (`scripts/fetch_vulns.py`)
- **実行環境:** Python 3.11+（標準ライブラリ `urllib.request`, `xml.etree.ElementTree`, `json`, `datetime`, `os`, `re` を基本とし、外部ライブラリ依存を最小限にする）
- **情報取得ソース:**
  1. **プライマリ: JVNDB公式新着RSS（RSS 1.0 / RDF）:** `https://jvndb.jvn.jp/ja/rss/jvndb_new.rdf` から最新の脆弱性情報を取得し、キーワード（`Java`, `OpenJDK`, `Spring`, `PHP`, `Apache`, `Nginx`, `OpenSSL`, `WordPress`）に該当する項目を抽出する。
  2. **セカンダリ（予備）: MyJVN API:** `https://jvndb.jvn.jp/myjvn?method=getVulnOverviewList&feed=hnd&rangeDatePublished=n&rangeDateFirstPublished=n`。2026-11 時点で HTTP 404 を返すため、プライマリ取得失敗時の予備としてのみ試行する。
  - **通信要件:** タイムアウト15秒、応答サイズ上限5MB。DTD/ENTITY宣言を含むXMLは安全のため拒否する。いずれのソースも失敗した場合は下記フォールバックモードへ移行する。
  3. **フォールバック／デモデータ生成モード:** ネットワーク制限やAPI応答遅延・該当件数不足時でもデモが確実に動作するよう、直近の実際の脆弱性・バージョンアップ事例（Java / Spring Boot / PHP / Apache HTTP Server 等）に基づくリアルな日本語データ（8〜10件）を補完・出力する。
- **AIトリアージ・要約ロジック:**
  - 環境変数 `GEMINI_API_KEY` または `ANTHROPIC_API_KEY` がある場合はLLM APIを呼び出して中小企業向けの平易な要約・推奨アクションを生成する（両方ある場合は Gemini を優先）。
  - Anthropic 利用時のモデルIDは環境変数 `ANTHROPIC_MODEL` で指定する。未設定・不正形式の場合は現行世代の軽量モデル `claude-haiku-5-5` を使用する。
  - LLM APIが回復不能なエラー（HTTP 400/401/403/404：モデルID誤り・認証失敗等）を返した場合、その実行中はLLMを停止し、残りの項目をルールベースで処理する。一時的なエラー（429/5xx・タイムアウト）や応答形式不正の場合は該当項目のみルールベースで処理する。
  - APIキー未設定時は、CVSSスコア・キーワードに基づくルールベース変換エンジンにより、同等の日本語要約・緊急度判定・推奨アクションを自動生成する。
- **出力先:** `public/data/vulnerabilities.json`（UTF-8 / インデント付きJSON）

## 3. JSONデータスキーマ (`public/data/vulnerabilities.json`)
```json
{
  "updated_at": "2026-11-24T20:00:00+09:00",
  "source_mode": "live_and_curated",
  "items": [
    {
      "id": "JVNDB-2026-001234",
      "cve_id": "CVE-2026-12345",
      "title": "PHP 8.2 / 8.3 系におけるリクエスト処理の脆弱性",
      "category": "PHP",
      "severity": "critical",
      "severity_label": "緊急",
      "cvss_score": 9.1,
      "published_date": "2026-11-22",
      "affected_versions": "PHP 8.2.0 〜 8.2.24 / 8.3.0 〜 8.3.12",
      "summary_3lines": [
        "外部からの細工されたHTTPリクエストにより、Webサーバーが異常終了または不正なコードを実行される恐れがあります。",
        "インターネットに公開されている問い合わせフォームやCMS（WordPress等）をPHPで運用している企業は影響を受けます。",
        "放置すると顧客情報の漏洩やWebサイト改ざんにつながるため、早急なバージョン確認が必要です。"
      ],
      "recommended_action": "利用中のPHPバージョンを確認し、最新の修正済みマイナーバージョン（8.2.25以降 / 8.3.13以降）へのアップデートを計画してください。",
      "source_url": "[https://jvndb.jvn.jp/](https://jvndb.jvn.jp/)"
    }
  ]
}
```
- `category` の値域: `"Java"`, `"PHP"`, `"Middleware"`（Webサーバー・DB・CMS等）
- `severity` の値域: `"critical"`（緊急: CVSS 9.0以上）, `"high"`（重要: CVSS 7.0〜8.9）, `"medium"`（注意: CVSS 4.0〜6.9）

## 4. フロントエンド画面仕様 (`public/index.html`, `style.css`, `app.js`)
- **デザイン方針:**
  - 1画面で全体像が把握できるクリーンなエンタープライズSaaS風UI（白ベース＋ネイビー／ブルーアクセント、視認性の高いバッジ配色）。
  - 初回表示時にスクロールなしでKPIサマリーと最新の緊急案件が視界に入るコンパクトなヘッダー構成。
- **画面構成要素:**
  1. **ヘッダーエリア:** タイトル「AX Vuln Radar」、サブタイトル「中小企業向け 脆弱性・バージョン情報 AIトリアージ」、最終更新日時バッジ。
  2. **KPIサマリーバー（4カード横並び）:** 監視対象件数（全件）、緊急対応（Critical）件数、重要対応（High）件数、対象技術領域（Java / PHP / Middleware）。
  3. **フィルタ＆検索バー:**
     - カテゴリタブ：`すべて` / `Java・Spring` / `PHP` / `Webサーバー・その他`
     - 緊急度フィルタ：`すべて` / `緊急のみ` / `重要以上`
     - キーワード検索ボックス（リアルタイム絞り込み）
  4. **脆弱性・バージョン情報カードリスト:**
     - 上段：緊急度バッジ、カテゴリタグ、CVE/JVN ID、CVSSスコア、公開日、公式情報リンク
     - タイトル＆影響バージョン表示
     - **AI平易解説ボックス（何が危険か）:** 3行の箇条書きでわかりやすく表示
     - **推奨アクションボックス:** 情シス・BPO担当者が次に取るべき具体的行動
     - **アクションボタン：「Chatwork報告文をコピー」**
       - クリックすると以下のChatwork記法（`[info][title]` タグ）フォーマット済みテキストをクリップボードにコピーし、「Chatwork報告用テンプレートをコピーしました」のトースト通知を表示する。
       ```text
       [info][title]【セキュリティ注意喚起・緊急度：{severity_label}】{title}[/title]■対象技術・影響バージョン
       {category}（{affected_versions}）
       ■識別番号・公開日
       {id} / {cve_id}（公開日: {published_date} / CVSS: {cvss_score}）

       ■概要（何が危険か）
       ・{summary_3lines[0]}
       ・{summary_3lines[1]}
       ・{summary_3lines[2]}

       ■推奨される対応アクション
       {recommended_action}

       ■詳細情報URL
       {source_url}[/info]
       ```
- **セキュリティ実装要件:**
  - JSONから読み込んだ文字列はすべて `textContent` または DOM API（`document.createElement`）で組み立て、`innerHTML` は一切使用しない。
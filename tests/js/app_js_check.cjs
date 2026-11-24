"use strict";
/**
 * public/app.js の純粋関数（URL検証・サニタイズ・Chatworkテンプレート・フィルタ）の検証スクリプト。
 * tests/test_app_js.py から Node.js で実行される。失敗時は例外で非0終了する。
 */
const assert = require("node:assert/strict");
const path = require("node:path");

const app = require(path.resolve(process.argv[2]));
const results = [];
function check(name, fn) {
  fn();
  results.push(name);
}

check("isSafeHttpUrl: 許可", () => {
  assert.equal(app.isSafeHttpUrl("https://jvndb.jvn.jp/"), "https://jvndb.jvn.jp/");
  assert.equal(app.isSafeHttpUrl("  http://example.com/a?b=1  "), "http://example.com/a?b=1");
});

check("isSafeHttpUrl: 拒否", () => {
  for (const bad of [
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "https://",
    "https://user:pass@evil.example.com/",
    "https://exa mple.com/",
    "https://example.com/\u0000",
    "//evil.example.com",
    "",
    null,
    undefined,
    42,
    { toString: () => "https://x" },
  ]) {
    assert.equal(app.isSafeHttpUrl(bad), "", `拒否されるべきURL: ${String(bad)}`);
  }
});

check("resolveSourceUrl: jvndb.jvn.jp のみ NVD / jvn.jp へ変換し jvn.jp 個別URLは保持", () => {
  assert.equal(
    app.resolveSourceUrl("https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-044605.html", "CVE-2026-90436"),
    "https://nvd.nist.gov/vuln/detail/CVE-2026-90436"
  );
  assert.equal(
    app.resolveSourceUrl("https://jvndb.jvn.jp/", "cve-2026-21480"),
    "https://nvd.nist.gov/vuln/detail/CVE-2026-21480"
  );
  assert.equal(
    app.resolveSourceUrl("https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html", "N/A"),
    "https://jvn.jp/"
  );
  assert.equal(
    app.resolveSourceUrl("https://jvndb.jvn.jp/", "invalid"),
    "https://jvn.jp/"
  );
  assert.equal(
    app.resolveSourceUrl("https://jvn.jp/vu/JVNVU99608534/", "CVE-2026-114938"),
    "https://jvn.jp/vu/JVNVU99608534/"
  );
  assert.equal(
    app.resolveSourceUrl("https://jvn.jp/jp/JVN84156789/", "N/A"),
    "https://jvn.jp/jp/JVN84156789/"
  );
  assert.equal(
    app.resolveSourceUrl("https://www.php.net/ChangeLog-8.php", "CVE-2026-18411"),
    "https://www.php.net/ChangeLog-8.php"
  );
  assert.equal(
    app.resolveSourceUrl("https://www.oracle.com/security-alerts/", "CVE-2026-20941"),
    "https://www.oracle.com/security-alerts/"
  );
  assert.equal(
    app.resolveSourceUrl("https://spring.io/security", "CVE-2026-22234"),
    "https://spring.io/security"
  );
  assert.equal(
    app.resolveSourceUrl("https://httpd.apache.org/security/vulnerabilities_24.html", "CVE-2026-22510"),
    "https://httpd.apache.org/security/vulnerabilities_24.html"
  );
  assert.equal(app.resolveSourceUrl("javascript:alert(1)", "CVE-2026-11111"), "");
});

check("getOfficialAdvisoryUrl: 公式セキュリティアドバイザリ一覧URL", () => {
  assert.equal(app.getOfficialAdvisoryUrl("PHP", "PHP 8.3 系の脆弱性"), "https://www.php.net/ChangeLog-8.php");
  assert.equal(app.getOfficialAdvisoryUrl("Java", "Oracle Java SE / OpenJDK"), "https://www.oracle.com/security-alerts/");
  assert.equal(app.getOfficialAdvisoryUrl("Java", "Spring Framework 認証バイパス"), "https://spring.io/security");
  assert.equal(
    app.getOfficialAdvisoryUrl("Middleware", "Apache HTTP Server 2.4 系"),
    "https://httpd.apache.org/security/vulnerabilities_24.html"
  );
  assert.equal(app.getOfficialAdvisoryUrl("Middleware", "OpenSSL 3.0 の脆弱性"), "https://jvn.jp/");
});

check("neutralizeChatworkTags", () => {
  assert.equal(app.neutralizeChatworkTags("a[/info][toall]b"), "a［/info］［toall］b");
  assert.equal(app.neutralizeChatworkTags("[To:123]x"), "［To:123］x");
  assert.equal(app.neutralizeChatworkTags("[Java] 配列[0]"), "[Java] 配列[0]");
  assert.equal(app.neutralizeChatworkTags(undefined), "");
  assert.equal(app.neutralizeChatworkTags("a‮b\u0000c"), "abc");
});

check("normalizeCvssScore", () => {
  assert.equal(app.normalizeCvssScore(9.8), "9.8");
  assert.equal(app.normalizeCvssScore("7"), "7.0");
  assert.equal(app.normalizeCvssScore(null), "-");
  assert.equal(app.normalizeCvssScore("abc"), "-");
  assert.equal(app.normalizeCvssScore(NaN), "-");
});

check("normalizeItem: 不正値の正規化", () => {
  assert.equal(app.normalizeItem(null), null);
  assert.equal(app.normalizeItem("str"), null);
  assert.equal(app.normalizeItem([1]), null);
  const item = app.normalizeItem({
    id: { evil: true },
    title: "<img src=x onerror=alert(1)>",
    category: "<b>",
    severity: "__proto__",
    severity_label: "<script>",
    cvss_score: "Infinity",
    summary_3lines: ["a", 1, null, "b", "c", "d"],
    source_url: "javascript:alert(1)",
  });
  assert.equal(item.id, "");
  assert.equal(item.title, "<img src=x onerror=alert(1)>"); // 文字列として保持し textContent で描画
  assert.equal(item.category, "Middleware");
  assert.equal(item.severity, "medium");
  assert.equal(item.severity_label, "注意");
  assert.equal(item.cvss_score, null);
  assert.equal(item.summary_3lines.length, 2);
  assert.equal(item.source_url, "");
  assert.equal(item.cve_id, "N/A");

  const jvnItem = app.normalizeItem({
    id: "JVNDB-2026-000001",
    cve_id: "CVE-2026-12345",
    source_url: "https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html",
  });
  assert.equal(jvnItem.source_url, "https://nvd.nist.gov/vuln/detail/CVE-2026-12345");
});

check("normalizeItems: 配列以外・不正要素の除外", () => {
  assert.deepEqual(app.normalizeItems(null), []);
  assert.deepEqual(app.normalizeItems({}), []);
  const items = app.normalizeItems([null, 1, { title: "ok", severity: "critical" }]);
  assert.equal(items.length, 1);
  assert.equal(items[0].severity_label, "緊急");
  assert.equal(app.normalizeItems(new Array(500).fill({})).length, 200);
});

const sampleItem = {
  id: "JVNDB-2026-004055",
  cve_id: "CVE-2026-21480",
  title: "PHP 8.2 / 8.3 系の脆弱性",
  category: "PHP",
  severity: "critical",
  severity_label: "緊急",
  cvss_score: 9.1,
  published_date: "2026-11-24",
  affected_versions: "PHP 8.2.0 〜 8.2.26",
  summary_3lines: ["一行目", "二行目", "三行目"],
  recommended_action: "アップデートしてください。",
  source_url: "https://jvndb.jvn.jp/",
};

check("formatChatworkTemplate: SPEC書式", () => {
  const expected = [
    "[info][title]【セキュリティ注意喚起・緊急度：緊急】PHP 8.2 / 8.3 系の脆弱性[/title]■対象技術・影響バージョン",
    "PHP（PHP 8.2.0 〜 8.2.26）",
    "■識別番号・公開日",
    "JVNDB-2026-004055 / CVE-2026-21480（公開日: 2026-11-24 / CVSS: 9.1）",
    "",
    "■概要（何が危険か）",
    "・一行目",
    "・二行目",
    "・三行目",
    "",
    "■推奨される対応アクション",
    "アップデートしてください。",
    "",
    "■詳細情報URL",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-21480[/info]",
  ].join("\n");
  assert.equal(app.formatChatworkTemplate(sampleItem), expected);
});

check("formatChatworkTemplate: タグ注入の無効化", () => {
  const text = app.formatChatworkTemplate({
    ...sampleItem,
    title: "x[/title][/info][toall]",
    summary_3lines: ["[To:1]a", "[info]b", "c"],
    recommended_action: "[/info]偽の枠外テキスト",
    source_url: "javascript:alert(1)",
  });
  // 先頭と末尾の正規タグ以外に生のタグが現れないこと
  assert.equal((text.match(/\[info\]/g) || []).length, 1);
  assert.equal((text.match(/\[\/info\]/g) || []).length, 1);
  assert.equal((text.match(/\[\/title\]/g) || []).length, 1);
  assert.ok(!/\[toall\]/i.test(text));
  assert.ok(!/\[To:/i.test(text));
  assert.ok(text.endsWith("https://jvn.jp/[/info]"), "不正URLは既定URLに置換");
});

check("formatChatworkTemplate: 欠損データでも例外にならない", () => {
  const text = app.formatChatworkTemplate({});
  assert.ok(text.startsWith("[info][title]"));
  assert.ok(text.includes("CVSS: -"));
  assert.doesNotThrow(() => app.formatChatworkTemplate(null));
});

check("filterItems", () => {
  const items = [
    { ...sampleItem, id: "a", category: "PHP", severity: "critical" },
    { ...sampleItem, id: "b", category: "Java", severity: "high", title: "Spring Framework" },
    { ...sampleItem, id: "c", category: "Middleware", severity: "medium", title: "OpenSSL" },
    null,
  ];
  const ids = (list) => list.map((i) => i.id);
  assert.deepEqual(ids(app.filterItems(items, {})), ["a", "b", "c"]);
  assert.deepEqual(ids(app.filterItems(items, { category: "Java" })), ["b"]);
  assert.deepEqual(ids(app.filterItems(items, { severity: "critical" })), ["a"]);
  assert.deepEqual(ids(app.filterItems(items, { severity: "high_or_above" })), ["a", "b"]);
  assert.deepEqual(ids(app.filterItems(items, { keyword: "  spring  " })), ["b"]);
  assert.deepEqual(ids(app.filterItems(items, { keyword: "<script>" })), []);
  assert.deepEqual(app.filterItems(null, {}), []);
});

check("formatUpdatedAt / getSourceModeLabel", () => {
  assert.equal(app.formatUpdatedAt("2026-11-24T20:00:00+09:00"), "2026/11/24 20:00 JST");
  assert.equal(app.formatUpdatedAt(""), "取得時刻不明");
  assert.equal(app.getSourceModeLabel("curated_fallback"), "デモデータ");
  assert.equal(app.getSourceModeLabel("<x>"), "データ読込済");
});

console.log(`OK ${results.length} checks`);

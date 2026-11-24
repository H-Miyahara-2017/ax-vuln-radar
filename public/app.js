"use strict";

/**
 * AX Vuln Radar フロントエンド制御スクリプト
 * セキュリティ規約に基づき、すべてのDOM生成は textContent / createElement で行います。
 */

const DATA_URL = "./data/vulnerabilities.json";
const FALLBACK_SOURCE_URL = "https://www.ipa.go.jp/security/";
const NVD_DETAIL_BASE_URL = "https://nvd.nist.gov/vuln/detail/";
const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/i;
const SVG_NS = "http://www.w3.org/2000/svg";
const FETCH_TIMEOUT_MS = 10000;
const MAX_ITEMS = 200;
const MAX_TEXT_LENGTH = 1000;
const VALID_CATEGORIES = ["Java", "PHP", "Middleware"];
const SEVERITY_LABELS = { critical: "緊急", high: "重要", medium: "注意" };

/** 制御文字・Unicode双方向制御文字（表示偽装の防止） */
const CONTROL_CHARS_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f​-‏‪-‮⁦-⁩﻿]/g;
/** Chatwork記法タグ（報告文へのタグ注入・[toall]等による一斉通知の悪用を防止） */
const CHATWORK_TAG_RE =
  /\[(\/?)(info|title|code|hr|qt|qtmeta|toall|to|rp|re|picon|piconname|preview|download|task|dtext|deleted)\b([^[\]]*)\]/gi;

/** ダッシュボード状態 */
const state = {
  items: [],
  updatedAt: "",
  sourceMode: "",
  category: "all",
  severity: "all",
  keyword: "",
  toastTimerId: null,
};

/**
 * http/https スキームのURLのみ許可する（XSS対策）
 * @param {unknown} rawUrl
 * @returns {string}
 */
function isSafeHttpUrl(rawUrl) {
  if (typeof rawUrl !== "string") {
    return "";
  }
  const trimmed = rawUrl.trim();
  if (!trimmed || /[\s\u0000-\u001f\u007f]/.test(trimmed)) {
    return "";
  }
  // 先頭一致ではなくURLパーサで判定し、スキーム・ホスト・認証情報埋め込みを厳密に検証する
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch (_err) {
    return "";
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return "";
  }
  if (!parsed.hostname || parsed.username || parsed.password) {
    return "";
  }
  return trimmed;
}

/**
 * 参照URLを正規化し、停止中の jvndb.jvn.jp をNVD個別詳細またはIPAへ変換する
 * @param {unknown} rawUrl
 * @param {unknown} rawCveId
 * @returns {string}
 */
function resolveSourceUrl(rawUrl, rawCveId) {
  const safeUrl = isSafeHttpUrl(rawUrl);
  if (!safeUrl) {
    return "";
  }
  if (safeUrl.toLowerCase().includes("jvndb.jvn.jp")) {
    const cveText = toSafeText(rawCveId, 64).toUpperCase();
    if (CVE_ID_RE.test(cveText)) {
      return `${NVD_DETAIL_BASE_URL}${cveText}`;
    }
    return FALLBACK_SOURCE_URL;
  }
  return safeUrl;
}

/**
 * 外部由来の値を表示・コピー用の安全な文字列に正規化する
 * （文字列以外は空文字、制御文字除去、長さ制限）
 * @param {unknown} value
 * @param {number} [maxLength]
 * @returns {string}
 */
function toSafeText(value, maxLength = MAX_TEXT_LENGTH) {
  if (typeof value !== "string" && typeof value !== "number") {
    return "";
  }
  const text = String(value).replace(CONTROL_CHARS_RE, "").trim();
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

/**
 * Chatwork記法タグの角括弧を全角化し、コピー文面内でタグとして解釈されないようにする
 * @param {unknown} value
 * @returns {string}
 */
function neutralizeChatworkTags(value) {
  return toSafeText(value).replace(CHATWORK_TAG_RE, (_m, slash, name, rest) => `［${slash}${name}${rest}］`);
}

/**
 * JSONから読み込んだ1件をスキーマに沿って正規化する（不正な型は既定値に置換）
 * @param {unknown} raw
 * @returns {Record<string, any> | null}
 */
function normalizeItem(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return null;
  }
  const severity = Object.prototype.hasOwnProperty.call(SEVERITY_LABELS, raw.severity) ? raw.severity : "medium";
  const category = VALID_CATEGORIES.includes(raw.category) ? raw.category : "Middleware";
  const summary = Array.isArray(raw.summary_3lines)
    ? raw.summary_3lines.slice(0, 3).map((line) => toSafeText(line)).filter(Boolean)
    : [];
  const score = Number(raw.cvss_score);
  const cveId = toSafeText(raw.cve_id, 64) || "N/A";
  return {
    id: toSafeText(raw.id, 64),
    cve_id: cveId,
    title: toSafeText(raw.title),
    category,
    severity,
    severity_label: SEVERITY_LABELS[severity],
    cvss_score: Number.isFinite(score) && score >= 0 && score <= 10 ? score : null,
    published_date: toSafeText(raw.published_date, 32),
    affected_versions: toSafeText(raw.affected_versions),
    summary_3lines: summary,
    recommended_action: toSafeText(raw.recommended_action),
    source_url: resolveSourceUrl(raw.source_url, cveId),
  };
}

/**
 * JSONペイロードのitems配列を正規化する（不正要素は除外、件数上限あり）
 * @param {unknown} rawItems
 * @returns {Array<Record<string, any>>}
 */
function normalizeItems(rawItems) {
  if (!Array.isArray(rawItems)) {
    return [];
  }
  return rawItems.slice(0, MAX_ITEMS).map(normalizeItem).filter((item) => item !== null);
}

/**
 * CVSSスコアを小数点1桁の表示用文字列へ正規化する
 * @param {unknown} rawScore
 * @returns {string}
 */
function normalizeCvssScore(rawScore) {
  if (rawScore === null || rawScore === undefined || rawScore === "") {
    return "-";
  }
  const num = Number(rawScore);
  if (Number.isFinite(num)) {
    return num.toFixed(1);
  }
  return "-";
}

/**
 * ISO8601日時文字列を「YYYY/MM/DD HH:MM JST」形式へ整形する
 * @param {unknown} rawIso
 * @returns {string}
 */
function formatUpdatedAt(rawIso) {
  if (typeof rawIso !== "string" || !rawIso.trim()) {
    return "取得時刻不明";
  }
  const match = rawIso.trim().match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
  if (match) {
    return `${match[1]}/${match[2]}/${match[3]} ${match[4]}:${match[5]} JST`;
  }
  return rawIso.trim();
}

/**
 * データ取得モードの日本語表示ラベルを返す
 * @param {unknown} mode
 * @returns {string}
 */
function getSourceModeLabel(mode) {
  switch (mode) {
    case "live":
      return "JVNDBリアルタイム";
    case "live_and_curated":
      return "JVNDB連携＋補完";
    case "curated_fallback":
      return "デモデータ";
    default:
      return "データ読込済";
  }
}

/**
 * Chatwork記法（[info][title]タグ）の報告文テンプレートを生成する
 * @param {Record<string, any>} item
 * @returns {string}
 */
function formatChatworkTemplate(item) {
  const src = item && typeof item === "object" ? item : {};
  // 埋め込む値はすべて Chatwork タグを無効化してから差し込む（[/info] での枠脱出や [toall] 注入を防止）
  const t = (value) => neutralizeChatworkTags(value);
  const summaryLines = Array.isArray(src.summary_3lines) ? src.summary_3lines : [];
  const line0 = t(summaryLines[0]);
  const line1 = t(summaryLines[1]);
  const line2 = t(summaryLines[2]);
  const safeUrl = resolveSourceUrl(src.source_url, src.cve_id) || FALLBACK_SOURCE_URL;
  const scoreText = normalizeCvssScore(src.cvss_score);

  return [
    `[info][title]【セキュリティ注意喚起・緊急度：${t(src.severity_label)}】${t(src.title)}[/title]■対象技術・影響バージョン`,
    `${t(src.category)}（${t(src.affected_versions)}）`,
    "■識別番号・公開日",
    `${t(src.id)} / ${t(src.cve_id)}（公開日: ${t(src.published_date)} / CVSS: ${scoreText}）`,
    "",
    "■概要（何が危険か）",
    `・${line0}`,
    `・${line1}`,
    `・${line2}`,
    "",
    "■推奨される対応アクション",
    `${t(src.recommended_action)}`,
    "",
    "■詳細情報URL",
    `${safeUrl}[/info]`,
  ].join("\n");
}

/**
 * カテゴリ・緊急度・キーワード条件でアイテム配列を絞り込む
 * @param {Array<Record<string, any>>} items
 * @param {{ category?: string, severity?: string, keyword?: string }} filters
 * @returns {Array<Record<string, any>>}
 */
function filterItems(items, filters) {
  const list = Array.isArray(items) ? items : [];
  const category = filters?.category || "all";
  const severity = filters?.severity || "all";
  const rawKeyword = typeof filters?.keyword === "string" ? filters.keyword.trim().toLowerCase() : "";
  const terms = rawKeyword ? rawKeyword.split(/\s+/).filter(Boolean) : [];

  return list.filter((item) => {
    if (!item || typeof item !== "object") {
      return false;
    }
    if (category !== "all" && item.category !== category) {
      return false;
    }

    if (severity === "critical" && item.severity !== "critical") {
      return false;
    }
    if (severity === "high_or_above" && item.severity !== "critical" && item.severity !== "high") {
      return false;
    }

    if (terms.length > 0) {
      const summaryText = Array.isArray(item.summary_3lines) ? item.summary_3lines.join(" ") : "";
      const searchable = [
        item.id,
        item.cve_id,
        item.title,
        item.category,
        item.severity_label,
        item.affected_versions,
        summaryText,
        item.recommended_action,
      ]
        .filter((v) => typeof v === "string")
        .join(" ")
        .toLowerCase();

      if (!terms.every((term) => searchable.includes(term))) {
        return false;
      }
    }

    return true;
  });
}

/**
 * 安全なSVGアイコン要素を生成する
 * @param {"external"|"copy"|"check"|"spark"|"shield"} kind
 * @returns {SVGSVGElement}
 */
function createIconSvg(kind) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "14");
  svg.setAttribute("height", "14");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");

  if (kind === "external") {
    const path1 = document.createElementNS(SVG_NS, "path");
    path1.setAttribute("d", "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6");
    const poly = document.createElementNS(SVG_NS, "polyline");
    poly.setAttribute("points", "15 3 21 3 21 9");
    const line = document.createElementNS(SVG_NS, "line");
    line.setAttribute("x1", "10");
    line.setAttribute("y1", "14");
    line.setAttribute("x2", "21");
    line.setAttribute("y2", "3");
    svg.append(path1, poly, line);
    return svg;
  }

  if (kind === "copy") {
    const rect = document.createElementNS(SVG_NS, "rect");
    rect.setAttribute("x", "9");
    rect.setAttribute("y", "9");
    rect.setAttribute("width", "13");
    rect.setAttribute("height", "13");
    rect.setAttribute("rx", "2");
    rect.setAttribute("ry", "2");
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1");
    svg.append(rect, path);
    return svg;
  }

  if (kind === "check") {
    const poly = document.createElementNS(SVG_NS, "polyline");
    poly.setAttribute("points", "20 6 9 17 4 12");
    svg.append(poly);
    return svg;
  }

  if (kind === "spark") {
    const circle = document.createElementNS(SVG_NS, "circle");
    circle.setAttribute("cx", "12");
    circle.setAttribute("cy", "12");
    circle.setAttribute("r", "9");
    const line1 = document.createElementNS(SVG_NS, "line");
    line1.setAttribute("x1", "12");
    line1.setAttribute("y1", "8");
    line1.setAttribute("x2", "12");
    line1.setAttribute("y2", "12");
    const line2 = document.createElementNS(SVG_NS, "line");
    line2.setAttribute("x1", "12");
    line2.setAttribute("y1", "16");
    line2.setAttribute("x2", "12.01");
    line2.setAttribute("y2", "16");
    svg.append(circle, line1, line2);
    return svg;
  }

  const shield = document.createElementNS(SVG_NS, "path");
  shield.setAttribute("d", "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z");
  svg.append(shield);
  return svg;
}

/**
 * トースト通知を表示する
 * @param {string} message
 */
function showToast(message) {
  const toastEl = document.getElementById("toast");
  if (!toastEl) {
    return;
  }
  toastEl.textContent = message;
  toastEl.hidden = false;
  toastEl.classList.add("is-visible");

  if (state.toastTimerId !== null) {
    clearTimeout(state.toastTimerId);
  }
  state.toastTimerId = window.setTimeout(() => {
    toastEl.classList.remove("is-visible");
    toastEl.hidden = true;
    state.toastTimerId = null;
  }, 3000);
}

/**
 * 文字列をクリップボードへコピーする（Clipboard API＋フォールバック）
 * @param {string} text
 * @returns {Promise<void>}
 */
async function copyTextToClipboard(text) {
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "readonly");
  textarea.style.position = "fixed";
  textarea.style.top = "-9999px";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  const succeeded = document.execCommand("copy");
  document.body.removeChild(textarea);
  if (!succeeded) {
    throw new Error("クリップボードへのコピーに失敗しました。");
  }
}

/**
 * ヘッダーメタ領域を更新する
 */
function renderHeaderMeta() {
  const modeBadge = document.getElementById("source-mode-badge");
  const updatedBadge = document.getElementById("updated-at-badge");
  if (modeBadge) {
    modeBadge.textContent = getSourceModeLabel(state.sourceMode);
  }
  if (updatedBadge) {
    updatedBadge.textContent = `最終更新: ${formatUpdatedAt(state.updatedAt)}`;
  }
}

/**
 * KPIサマリーバーを更新する
 * @param {number} filteredCount
 */
function renderKpi(filteredCount) {
  const totalCount = state.items.length;
  const criticalCount = state.items.filter((i) => i.severity === "critical").length;
  const highCount = state.items.filter((i) => i.severity === "high").length;

  const javaCount = state.items.filter((i) => i.category === "Java").length;
  const phpCount = state.items.filter((i) => i.category === "PHP").length;
  const mwCount = state.items.filter((i) => i.category === "Middleware").length;

  const totalEl = document.getElementById("kpi-total");
  const totalSubEl = document.getElementById("kpi-total-sub");
  const criticalEl = document.getElementById("kpi-critical");
  const highEl = document.getElementById("kpi-high");
  const categoriesEl = document.getElementById("kpi-categories");

  if (totalEl) {
    totalEl.textContent = String(totalCount);
  }
  if (totalSubEl) {
    totalSubEl.textContent =
      filteredCount === totalCount
        ? "全件を表示中・クリックで解除"
        : `現在 ${filteredCount}件 を絞り込み表示中`;
  }
  if (criticalEl) {
    criticalEl.textContent = String(criticalCount);
  }
  if (highEl) {
    highEl.textContent = String(highCount);
  }
  if (categoriesEl) {
    const entries = [
      `Java: ${javaCount}`,
      `PHP: ${phpCount}`,
      `Middleware: ${mwCount}`,
    ];
    const pills = entries.map((label) => {
      const span = document.createElement("span");
      span.className = "tech-pill";
      span.textContent = label;
      return span;
    });
    categoriesEl.replaceChildren(...pills);
  }
}

/**
 * フィルタUIのアクティブ表示と件数・リセットボタンを更新する
 * @param {number} filteredCount
 */
function syncFilterControls(filteredCount) {
  const catButtons = document.querySelectorAll("#category-tabs .tab-btn");
  catButtons.forEach((btn) => {
    const isActive = btn.dataset.category === state.category;
    btn.classList.toggle("is-active", isActive);
    btn.setAttribute("aria-selected", isActive ? "true" : "false");
  });

  const sevButtons = document.querySelectorAll("#severity-filters .sev-btn");
  sevButtons.forEach((btn) => {
    const isActive = btn.dataset.severity === state.severity;
    btn.classList.toggle("is-active", isActive);
    btn.setAttribute("aria-pressed", isActive ? "true" : "false");
  });

  const resultCountEl = document.getElementById("result-count");
  if (resultCountEl) {
    resultCountEl.textContent = `表示: ${filteredCount}件 / 全${state.items.length}件`;
  }

  const resetBtn = document.getElementById("reset-filters-button");
  if (resetBtn) {
    const hasFilter =
      state.category !== "all" ||
      state.severity !== "all" ||
      state.keyword.trim() !== "";
    resetBtn.hidden = !hasFilter;
  }
}

/**
 * 脆弱性カード1件分のDOM要素を生成する
 * @param {Record<string, any>} item
 * @returns {HTMLElement}
 */
function createVulnCard(item) {
  const severityKey =
    item.severity === "critical" || item.severity === "high" ? item.severity : "medium";

  const card = document.createElement("article");
  card.className = `vuln-card vuln-card--${severityKey}`;

  // 上段メタ行
  const metaRow = document.createElement("div");
  metaRow.className = "card-meta-row";

  const badgesWrap = document.createElement("div");
  badgesWrap.className = "card-badges";

  const sevBadge = document.createElement("span");
  sevBadge.className = `severity-badge severity-badge--${severityKey}`;
  sevBadge.textContent = item.severity_label || "注意";

  const catBadge = document.createElement("span");
  catBadge.className = "category-badge";
  catBadge.textContent = item.category || "Middleware";

  const idChip = document.createElement("span");
  idChip.className = "id-chip";
  idChip.textContent = `${item.id || "-"} / ${item.cve_id || "N/A"}`;

  const cvssChip = document.createElement("span");
  cvssChip.className = "cvss-chip";
  cvssChip.textContent = `CVSS ${normalizeCvssScore(item.cvss_score)}`;

  badgesWrap.append(sevBadge, catBadge, idChip, cvssChip);

  const metaRight = document.createElement("div");
  metaRight.className = "card-meta-right";

  const pubDate = document.createElement("span");
  pubDate.className = "published-date";
  pubDate.textContent = `公開日: ${item.published_date || "-"}`;
  metaRight.append(pubDate);

  const safeUrl = resolveSourceUrl(item.source_url, item.cve_id);
  if (safeUrl) {
    const link = document.createElement("a");
    link.className = "source-link";
    link.href = safeUrl;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    const linkText = document.createElement("span");
    linkText.textContent = "公式情報";
    link.append(linkText, createIconSvg("external"));
    metaRight.append(link);
  }

  metaRow.append(badgesWrap, metaRight);

  // タイトル・影響バージョン
  const titleEl = document.createElement("h2");
  titleEl.className = "card-title";
  titleEl.textContent = item.title || "(タイトルなし)";

  const affectedRow = document.createElement("div");
  affectedRow.className = "affected-row";
  const affectedLabel = document.createElement("span");
  affectedLabel.className = "affected-label";
  affectedLabel.textContent = "影響対象";
  const affectedText = document.createElement("span");
  affectedText.className = "affected-text";
  affectedText.textContent = item.affected_versions || "詳細は公式情報をご確認ください";
  affectedRow.append(affectedLabel, affectedText);

  // 本文2カラム（左: AI平易解説3行、右: 推奨アクション＋Chatworkコピー）
  const bodyGrid = document.createElement("div");
  bodyGrid.className = "card-body-grid";

  const summaryBox = document.createElement("div");
  summaryBox.className = "summary-box";

  const summaryHeading = document.createElement("h3");
  summaryHeading.className = "box-heading";
  const summaryHeadingText = document.createElement("span");
  summaryHeadingText.textContent = "AI平易解説（何が危険か）";
  summaryHeading.append(createIconSvg("spark"), summaryHeadingText);

  const summaryList = document.createElement("ul");
  summaryList.className = "summary-list";
  const lines = Array.isArray(item.summary_3lines) ? item.summary_3lines : [];
  lines.forEach((line) => {
    if (typeof line === "string" && line.trim()) {
      const li = document.createElement("li");
      li.textContent = line;
      summaryList.append(li);
    }
  });
  summaryBox.append(summaryHeading, summaryList);

  const actionCol = document.createElement("div");
  actionCol.className = "action-column";

  const actionBody = document.createElement("div");
  const actionHeading = document.createElement("h3");
  actionHeading.className = "box-heading";
  const actionHeadingText = document.createElement("span");
  actionHeadingText.textContent = "推奨アクション";
  actionHeading.append(createIconSvg("shield"), actionHeadingText);

  const actionText = document.createElement("p");
  actionText.className = "action-text";
  actionText.textContent = item.recommended_action || "最新バージョンの適用要否を確認してください。";
  actionBody.append(actionHeading, actionText);

  const footerActions = document.createElement("div");
  footerActions.className = "card-footer-actions";

  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.className = "btn-copy-cw";

  const renderCopyButtonLabel = (copied) => {
    const icon = createIconSvg(copied ? "check" : "copy");
    const span = document.createElement("span");
    span.textContent = copied ? "コピーしました" : "Chatwork報告文をコピー";
    copyBtn.replaceChildren(icon, span);
    copyBtn.classList.toggle("is-copied", copied);
  };

  renderCopyButtonLabel(false);

  let buttonResetTimer = null;
  copyBtn.addEventListener("click", async () => {
    const templateText = formatChatworkTemplate(item);
    try {
      await copyTextToClipboard(templateText);
      showToast("Chatwork報告用テンプレートをコピーしました");
      renderCopyButtonLabel(true);
      if (buttonResetTimer !== null) {
        clearTimeout(buttonResetTimer);
      }
      buttonResetTimer = window.setTimeout(() => {
        renderCopyButtonLabel(false);
        buttonResetTimer = null;
      }, 2200);
    } catch (_err) {
      showToast("クリップボードへのコピーに失敗しました。ブラウザ権限をご確認ください。");
    }
  });

  footerActions.append(copyBtn);
  actionCol.append(actionBody, footerActions);

  bodyGrid.append(summaryBox, actionCol);
  card.append(metaRow, titleEl, affectedRow, bodyGrid);
  return card;
}

/**
 * すべてのフィルタを初期状態に戻して再描画する
 */
function resetFilters() {
  state.category = "all";
  state.severity = "all";
  state.keyword = "";
  const searchInput = document.getElementById("search-input");
  if (searchInput) {
    searchInput.value = "";
  }
  renderDashboard();
}

/**
 * カードリスト領域を再描画する
 */
function renderDashboard() {
  const filtered = filterItems(state.items, {
    category: state.category,
    severity: state.severity,
    keyword: state.keyword,
  });

  renderKpi(filtered.length);
  syncFilterControls(filtered.length);

  const listEl = document.getElementById("vuln-list");
  if (!listEl) {
    return;
  }

  if (filtered.length === 0) {
    const emptyPanel = document.createElement("div");
    emptyPanel.className = "status-panel";

    const title = document.createElement("p");
    title.className = "status-panel-title";
    title.textContent = "条件に一致する脆弱性・バージョン情報はありません";

    const desc = document.createElement("p");
    desc.className = "status-panel-desc";
    desc.textContent = "検索キーワードやカテゴリ・緊急度フィルタの条件を変更して再度ご確認ください。";

    const clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.className = "btn-primary-outline";
    clearBtn.textContent = "フィルタをすべて解除";
    clearBtn.addEventListener("click", resetFilters);

    emptyPanel.append(title, desc, clearBtn);
    listEl.replaceChildren(emptyPanel);
    return;
  }

  const fragment = document.createDocumentFragment();
  filtered.forEach((item) => {
    fragment.append(createVulnCard(item));
  });
  listEl.replaceChildren(fragment);
}

/**
 * エラー状態をDOM APIで表示する
 * @param {string} detailMessage
 */
function renderError(detailMessage) {
  const listEl = document.getElementById("vuln-list");
  if (!listEl) {
    return;
  }
  const panel = document.createElement("div");
  panel.className = "status-panel status-panel--error";

  const title = document.createElement("p");
  title.className = "status-panel-title";
  title.textContent = "脆弱性データの読み込みに失敗しました";

  const desc = document.createElement("p");
  desc.className = "status-panel-desc";
  desc.textContent =
    `${detailMessage} ローカル環境で直接ファイルを開いている場合は、` +
    "「python -m http.server -d public 8000」等のHTTPサーバー経由でアクセスしてください。";

  const retryBtn = document.createElement("button");
  retryBtn.type = "button";
  retryBtn.className = "btn-primary-outline";
  retryBtn.textContent = "再読み込み";
  retryBtn.addEventListener("click", loadVulnerabilities);

  panel.append(title, desc, retryBtn);
  listEl.replaceChildren(panel);
}

/**
 * JSONデータを取得して画面全体を初期化する
 * @returns {Promise<boolean>} 読み込みに成功した場合 true
 */
async function loadVulnerabilities() {
  // 応答が返らない場合でも画面が固まらないよう、タイムアウトで中断する
  const controller = typeof AbortController === "function" ? new AbortController() : null;
  const timeoutId = controller ? window.setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS) : null;
  try {
    const response = await fetch(DATA_URL, {
      cache: "no-store",
      signal: controller ? controller.signal : undefined,
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    let payload;
    try {
      payload = await response.json();
    } catch (_parseErr) {
      throw new Error("JSONデータの解析に失敗しました。");
    }
    if (!payload || typeof payload !== "object" || !Array.isArray(payload.items)) {
      throw new Error("JSONデータ形式が不正です。");
    }
    state.items = normalizeItems(payload.items);
    state.updatedAt = typeof payload.updated_at === "string" ? toSafeText(payload.updated_at, 64) : "";
    state.sourceMode = typeof payload.source_mode === "string" ? payload.source_mode : "";

    renderHeaderMeta();
    renderDashboard();
    return true;
  } catch (err) {
    let message = "通信エラーが発生しました。";
    if (err && err.name === "AbortError") {
      message = "データ取得がタイムアウトしました。";
    } else if (err instanceof Error) {
      message = err.message;
    }
    renderError(message);
    return false;
  } finally {
    if (timeoutId !== null) {
      clearTimeout(timeoutId);
    }
  }
}

/**
 * UIイベントリスナーを登録する
 */
function bindEvents() {
  const catTabs = document.getElementById("category-tabs");
  if (catTabs) {
    catTabs.addEventListener("click", (event) => {
      const target = event.target instanceof Element ? event.target.closest(".tab-btn") : null;
      if (!target || !target.dataset.category) {
        return;
      }
      state.category = target.dataset.category;
      renderDashboard();
    });
  }

  const sevFilters = document.getElementById("severity-filters");
  if (sevFilters) {
    sevFilters.addEventListener("click", (event) => {
      const target = event.target instanceof Element ? event.target.closest(".sev-btn") : null;
      if (!target || !target.dataset.severity) {
        return;
      }
      state.severity = target.dataset.severity;
      renderDashboard();
    });
  }

  // KPIカードクリックによるクイック絞り込み
  document.querySelectorAll(".kpi-card[data-kpi-filter]").forEach((card) => {
    card.addEventListener("click", () => {
      const filterValue = card.dataset.kpiFilter;
      if (filterValue === "all") {
        resetFilters();
        return;
      }
      if (filterValue === "critical" || filterValue === "high_or_above") {
        state.severity = state.severity === filterValue ? "all" : filterValue;
        renderDashboard();
      }
    });
  });

  const searchInput = document.getElementById("search-input");
  if (searchInput) {
    searchInput.addEventListener("input", (event) => {
      const inputEl = event.target;
      state.keyword = inputEl && typeof inputEl.value === "string" ? inputEl.value : "";
      renderDashboard();
    });
  }

  const resetBtn = document.getElementById("reset-filters-button");
  if (resetBtn) {
    resetBtn.addEventListener("click", resetFilters);
  }

  const reloadBtn = document.getElementById("reload-button");
  if (reloadBtn) {
    reloadBtn.addEventListener("click", async () => {
      const ok = await loadVulnerabilities();
      showToast(ok ? "最新の脆弱性データを再読み込みしました" : "脆弱性データの再読み込みに失敗しました");
    });
  }
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    bindEvents();
    loadVulnerabilities();
  });
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    isSafeHttpUrl,
    resolveSourceUrl,
    toSafeText,
    neutralizeChatworkTags,
    normalizeItem,
    normalizeItems,
    normalizeCvssScore,
    formatUpdatedAt,
    getSourceModeLabel,
    formatChatworkTemplate,
    filterItems,
  };
}

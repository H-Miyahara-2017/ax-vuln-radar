"""JVNDB XMLパース、および外部API通信の異常系（タイムアウト・不正応答）のテスト。"""

from __future__ import annotations

import http.client
import json
import socket
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

import pytest

from conftest import FakeResponse, build_rdf, rdf_item

FALLBACK_DATE = "2026-11-24"


# --- parse_jvn_xml -----------------------------------------------------------


def test_parse_jvn_xml_basic_item(fv):
    items = fv.parse_jvn_xml(build_rdf(rdf_item()), FALLBACK_DATE)
    assert len(items) == 1
    item = items[0]
    assert item["id"] == "JVNDB-2026-000001"
    assert item["cve_id"] == "CVE-2026-11111"
    assert item["category"] == "PHP"
    assert item["cvss_score"] == 9.8
    assert (item["severity"], item["severity_label"]) == ("critical", "緊急")
    assert item["published_date"] == "2026-11-20"
    assert item["source_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-11111"


def test_parse_jvn_xml_jvn_link_without_cve_falls_back_to_ipa(fv):
    xml = build_rdf(
        rdf_item(
            link="https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000099.html",
            references="",
        )
    )
    item = fv.parse_jvn_xml(xml, FALLBACK_DATE)[0]
    assert item["cve_id"] == "N/A"
    assert item["source_url"] == "https://www.ipa.go.jp/security/"


def test_parse_jvn_xml_filters_non_target_keywords(fv):
    xml = build_rdf(
        rdf_item(title="Microsoft Exchange の脆弱性", description="メールサーバー")
        + rdf_item(title="JavaScript ライブラリの脆弱性", description="npm パッケージ", identifier="JVNDB-2026-000002")
        + rdf_item(title="OpenSSL の脆弱性", description="TLS", identifier="JVNDB-2026-000003")
    )
    items = fv.parse_jvn_xml(xml, FALLBACK_DATE)
    assert [i["id"] for i in items] == ["JVNDB-2026-000003"]


def test_parse_jvn_xml_prefers_cvss_v3(fv):
    cvss = (
        '<sec:cvss score="10.0" severity="High" version="2.0"/>'
        '<sec:cvss score="7.5" severity="High" version="3.1"/>'
    )
    items = fv.parse_jvn_xml(build_rdf(rdf_item(cvss=cvss)), FALLBACK_DATE)
    assert items[0]["cvss_score"] == 7.5
    assert items[0]["severity"] == "high"


@pytest.mark.parametrize(
    "cvss",
    [
        "",  # CVSS要素なし
        '<sec:cvss score="NaN" version="3.0"/>',
        '<sec:cvss score="Infinity" version="3.0"/>',
        '<sec:cvss score="99" version="3.0"/>',
        '<sec:cvss score="abc" version="3.0"/>',
    ],
)
def test_parse_jvn_xml_invalid_cvss_uses_default(fv, cvss):
    items = fv.parse_jvn_xml(build_rdf(rdf_item(cvss=cvss)), FALLBACK_DATE)
    assert items[0]["cvss_score"] == fv.DEFAULT_CVSS_SCORE
    # NaN が混入すると JSON が壊れるため、必ず有限値で出力されること
    json.dumps(items[0]["cvss_score"], allow_nan=False)


def test_parse_jvn_xml_sanitizes_untrusted_fields(fv):
    xml = build_rdf(
        rdf_item(
            link="javascript:alert(1)",
            identifier="&lt;script&gt;",
            references='<sec:references source="CVE" id="CVE-XSS-&lt;img&gt;"/>',
            issued="9999-99-99",
        )
    )
    item = fv.parse_jvn_xml(xml, FALLBACK_DATE)[0]
    assert item["source_url"] == fv.JVN_FALLBACK_LINK
    assert item["id"] == "JVNDB-LIVE-0001"
    assert item["cve_id"] == "N/A"
    assert item["published_date"] == FALLBACK_DATE


def test_parse_jvn_xml_extracts_cwe_titles(fv):
    refs = (
        '<sec:references source="CVE" id="CVE-2026-22222"/>'
        '<sec:references id="CWE-79" title="クロスサイトスクリプティング(CWE-79)"/>'
    )
    item = fv.parse_jvn_xml(build_rdf(rdf_item(references=refs)), FALLBACK_DATE)[0]
    assert item["cve_id"] == "CVE-2026-22222"
    assert item["cwes"] == ["クロスサイトスクリプティング(CWE-79)"]


def test_parse_jvn_xml_rejects_dtd_entity_expansion(fv):
    billion_laughs = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>'
        b"<rdf:RDF>&lol2;</rdf:RDF>"
    )
    with pytest.raises(ET.ParseError):
        fv.parse_jvn_xml(billion_laughs, FALLBACK_DATE)


def test_parse_jvn_xml_rejects_xxe(fv):
    xxe = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'
    )
    with pytest.raises(ET.ParseError):
        fv.parse_jvn_xml(xxe, FALLBACK_DATE)


@pytest.mark.parametrize("body", [b"", b"<html><body>503</body>", b"\xff\xfe\x00garbage", b'{"json": true}'])
def test_parse_jvn_xml_malformed_raises_parse_error_or_empty(fv, body):
    try:
        assert fv.parse_jvn_xml(body, FALLBACK_DATE) == []
    except ET.ParseError:
        pass


# --- fetch_live_jvn_items（通信異常時のフォールバック） ------------------------


def _patch_urlopen(monkeypatch, behavior):
    """各URL呼び出しごとに behavior(url) を実行するよう urlopen を差し替える。"""
    calls: list[str] = []

    def fake_urlopen(req, timeout=None):
        assert timeout == pytest.approx(15), "タイムアウト未指定の通信は禁止"
        url = req.full_url if isinstance(req, urllib.request.Request) else req
        calls.append(url)
        return behavior(url)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return calls


def _raiser(exc):
    def behavior(_url):
        raise exc

    return behavior


@pytest.mark.parametrize(
    "exc",
    [
        urllib.error.URLError("network unreachable"),
        urllib.error.HTTPError("https://x", 503, "Service Unavailable", {}, None),
        TimeoutError("timed out"),
        socket.timeout("timed out"),
        ConnectionResetError("reset"),
        http.client.IncompleteRead(b"partial"),
        http.client.RemoteDisconnected("closed"),
        RuntimeError("想定外の例外"),
    ],
)
def test_fetch_live_returns_empty_on_network_errors(fv, monkeypatch, exc):
    calls = _patch_urlopen(monkeypatch, _raiser(exc))
    assert fv.fetch_live_jvn_items(FALLBACK_DATE) == []
    # プライマリ失敗後にセカンダリも試行していること
    assert calls == [fv.PRIMARY_JVN_URL, fv.SECONDARY_JVN_URL]


@pytest.mark.parametrize("body", [b"<not-xml", b"<html>maintenance</html>", b"\x00\x01\x02"])
def test_fetch_live_returns_empty_on_invalid_xml(fv, monkeypatch, body):
    _patch_urlopen(monkeypatch, lambda _u: FakeResponse(body))
    assert fv.fetch_live_jvn_items(FALLBACK_DATE) == []


def test_fetch_live_rejects_oversized_response(fv, monkeypatch):
    monkeypatch.setattr(fv, "MAX_RESPONSE_BYTES", 100)
    big = build_rdf(rdf_item() * 5)
    assert len(big) > 100
    _patch_urlopen(monkeypatch, lambda _u: FakeResponse(big))
    assert fv.fetch_live_jvn_items(FALLBACK_DATE) == []


def test_fetch_live_falls_back_to_secondary(fv, monkeypatch):
    def behavior(url):
        if url == fv.PRIMARY_JVN_URL:
            raise urllib.error.URLError("primary down")
        return FakeResponse(build_rdf(rdf_item()))

    calls = _patch_urlopen(monkeypatch, behavior)
    items = fv.fetch_live_jvn_items(FALLBACK_DATE)
    assert len(items) == 1
    assert calls == [fv.PRIMARY_JVN_URL, fv.SECONDARY_JVN_URL]


# --- LLM API 呼び出し ----------------------------------------------------------


def test_gemini_api_key_is_sent_in_header_not_url(fv, monkeypatch):
    captured = {}
    gemini_resp = {
        "candidates": [{"content": {"parts": [{"text": json.dumps({"title": "t"})}]}}]
    }

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        return FakeResponse(json.dumps(gemini_resp).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    fv.call_gemini_triage("prompt", "SECRET-KEY-123")
    assert "SECRET-KEY-123" not in captured["url"]
    assert captured["headers"]["x-goog-api-key"] == "SECRET-KEY-123"


@pytest.mark.parametrize(
    "body",
    [b"[]", b'{"candidates": "x"}', b'{"candidates": [null]}', b'{"candidates": [{"content": []}]}'],
)
def test_gemini_unexpected_shapes_return_none(fv, monkeypatch, body):
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: FakeResponse(body))
    assert fv.call_gemini_triage("p", "k") is None


@pytest.mark.parametrize("body", [b"[]", b'{"content": "x"}', b'{"content": [null, 1]}'])
def test_anthropic_unexpected_shapes_return_none(fv, monkeypatch, body):
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: FakeResponse(body))
    assert fv.call_anthropic_triage("p", "k") is None


def test_triage_with_llm_skipped_without_api_key(fv, monkeypatch):
    def must_not_call(*_a, **_k):
        raise AssertionError("APIキー未設定時にLLMを呼び出してはならない")

    monkeypatch.setattr(fv, "call_gemini_triage", must_not_call)
    monkeypatch.setattr(fv, "call_anthropic_triage", must_not_call)
    raw = fv.parse_jvn_xml(build_rdf(rdf_item()), FALLBACK_DATE)[0]
    assert fv.triage_with_llm(raw) is None


@pytest.mark.parametrize(
    "side_effect",
    [
        urllib.error.URLError("down"),
        TimeoutError("timeout"),
        json.JSONDecodeError("bad", "doc", 0),
    ],
)
def test_triage_with_llm_failure_falls_back_to_rules(fv, monkeypatch, side_effect):
    monkeypatch.setenv("GEMINI_API_KEY", "dummy")

    def failing(*_a, **_k):
        raise side_effect

    monkeypatch.setattr(fv, "call_gemini_triage", failing)
    raw = fv.parse_jvn_xml(build_rdf(rdf_item()), FALLBACK_DATE)[0]
    assert fv.triage_with_llm(raw) is None
    out = fv.triage_item(raw)
    assert len(out["summary_3lines"]) == 3


def test_triage_item_sanitizes_malicious_llm_output(fv, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.setattr(
        fv,
        "call_anthropic_triage",
        lambda *_a, **_k: {
            "title": "[/info][toall]至急対応\x1b",
            "affected_versions": "PHP‮全バージョン",
            "summary_3lines": ["[To:111]危険", "2行目", "3行目"],
            "recommended_action": "x" * 5000,
        },
    )
    raw = fv.parse_jvn_xml(build_rdf(rdf_item()), FALLBACK_DATE)[0]
    out = fv.triage_item(raw)
    assert out["title"] == "［/info］［toall］至急対応"
    assert out["affected_versions"] == "PHP全バージョン"
    assert out["summary_3lines"][0] == "［To:111］危険"
    assert len(out["recommended_action"]) <= fv.MAX_LEN_ACTION
    # LLM は ID・深刻度・URL を書き換えられない
    assert out["id"] == raw["id"]
    assert out["severity"] == raw["severity"]
    assert out["source_url"] == raw["source_url"]


# --- 取得ソースの優先順位 ------------------------------------------------------


def test_primary_source_is_jvndb_official_rss(fv):
    assert fv.PRIMARY_JVN_URL == "https://jvndb.jvn.jp/ja/rss/jvndb_new.rdf"
    assert "myjvn" in fv.SECONDARY_JVN_URL


def test_fetch_live_uses_primary_rss_without_calling_secondary(fv, monkeypatch):
    calls = _patch_urlopen(monkeypatch, lambda _u: FakeResponse(build_rdf(rdf_item())))
    assert len(fv.fetch_live_jvn_items(FALLBACK_DATE)) == 1
    assert calls == [fv.PRIMARY_JVN_URL]


# --- Anthropic モデルID（ANTHROPIC_MODEL） ---------------------------------------


def test_resolve_anthropic_model_default(fv):
    assert fv.resolve_anthropic_model() == fv.DEFAULT_ANTHROPIC_MODEL == "claude-haiku-5-5"


def test_resolve_anthropic_model_from_env(fv, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_MODEL", "  claude-sonnet-5-5  ")
    assert fv.resolve_anthropic_model() == "claude-sonnet-5-5"


@pytest.mark.parametrize("bad", ['claude"}, "x": "y', "a b", "../etc", "-leading", "x" * 101])
def test_resolve_anthropic_model_invalid_falls_back_to_default(fv, monkeypatch, bad):
    monkeypatch.setenv("ANTHROPIC_MODEL", bad)
    assert fv.resolve_anthropic_model() == fv.DEFAULT_ANTHROPIC_MODEL


def _capture_anthropic_request(monkeypatch, response: dict):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["body"] = json.loads(req.data.decode("utf-8"))
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        return FakeResponse(json.dumps(response).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return captured


ANTHROPIC_OK = {
    "stop_reason": "end_turn",
    "content": [
        {"type": "thinking", "thinking": ""},
        {"type": "text", "text": json.dumps(VALID_LLM := {
            "title": "t", "affected_versions": "v",
            "summary_3lines": ["1", "2", "3"], "recommended_action": "a",
        })},
    ],
}


def test_anthropic_request_uses_env_model_and_no_sampling_params(fv, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-opus-5-5")
    captured = _capture_anthropic_request(monkeypatch, ANTHROPIC_OK)
    assert fv.call_anthropic_triage("p", "KEY") == VALID_LLM
    body = captured["body"]
    assert body["model"] == "claude-opus-5-5"
    assert body["max_tokens"] == fv.ANTHROPIC_MAX_TOKENS
    # 現行モデルは temperature 等の指定を 400 で拒否するため送らない
    for key in ("temperature", "top_p", "top_k"):
        assert key not in body
    assert captured["headers"]["x-api-key"] == "KEY"


def test_anthropic_request_default_model(fv, monkeypatch):
    captured = _capture_anthropic_request(monkeypatch, ANTHROPIC_OK)
    fv.call_anthropic_triage("p", "KEY")
    assert captured["body"]["model"] == "claude-haiku-5-5"


@pytest.mark.parametrize("stop_reason", ["max_tokens", "refusal"])
def test_anthropic_incomplete_response_returns_none(fv, monkeypatch, stop_reason):
    _capture_anthropic_request(monkeypatch, {**ANTHROPIC_OK, "stop_reason": stop_reason})
    assert fv.call_anthropic_triage("p", "KEY") is None


@pytest.mark.parametrize("code", [400, 401, 403, 404])
def test_llm_fatal_http_error_disables_llm_for_run(fv, monkeypatch, code):
    """モデルID誤り等の回復不能エラー後は、残りの項目でAPIを呼ばずルールベースで処理する。"""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-not-exist")
    calls = []

    def fake_call(*_a, **_k):
        calls.append(1)
        raise urllib.error.HTTPError("https://api.anthropic.com/v1/messages", code, "err", {}, None)

    monkeypatch.setattr(fv, "call_anthropic_triage", fake_call)
    raw = fv.parse_jvn_xml(build_rdf(rdf_item()), FALLBACK_DATE)[0]
    for _ in range(3):
        out = fv.triage_item(raw)
        assert len(out["summary_3lines"]) == 3  # ルールベースで出力される
    assert len(calls) == 1
    assert fv._llm_disabled_reason == f"HTTP {code}"


@pytest.mark.parametrize("code", [429, 500, 529])
def test_llm_transient_http_error_keeps_llm_enabled(fv, monkeypatch, code):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    calls = []

    def fake_call(*_a, **_k):
        calls.append(1)
        raise urllib.error.HTTPError("https://api.anthropic.com/v1/messages", code, "err", {}, None)

    monkeypatch.setattr(fv, "call_anthropic_triage", fake_call)
    raw = fv.parse_jvn_xml(build_rdf(rdf_item()), FALLBACK_DATE)[0]
    fv.triage_item(raw)
    fv.triage_item(raw)
    assert len(calls) == 2
    assert fv._llm_disabled_reason == ""

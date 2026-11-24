"""フォールバックJSON出力・データセット構築・ファイル書き出しのテスト。"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from conftest import PROJECT_ROOT, build_rdf, rdf_item

SEVERITY_LABELS = {"critical": "緊急", "high": "重要", "medium": "注意"}
ITEM_KEYS = {
    "id", "cve_id", "title", "category", "severity", "severity_label", "cvss_score",
    "published_date", "affected_versions", "summary_3lines", "recommended_action", "source_url",
}


def _reject_constant(name):
    raise ValueError(f"JSONに不正な定数 {name} が含まれています")


def assert_spec_schema(dataset: dict) -> None:
    """SPEC.md セクション3 のスキーマ・値域に準拠していることを検証する。"""
    assert set(dataset) == {"updated_at", "source_mode", "items"}
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+09:00$", dataset["updated_at"])
    assert dataset["source_mode"] in {"live", "live_and_curated", "curated_fallback"}
    assert isinstance(dataset["items"], list) and dataset["items"]

    for item in dataset["items"]:
        assert set(item) == ITEM_KEYS
        assert item["category"] in {"Java", "PHP", "Middleware"}
        assert item["severity"] in SEVERITY_LABELS
        assert item["severity_label"] == SEVERITY_LABELS[item["severity"]]
        score = item["cvss_score"]
        assert isinstance(score, (int, float)) and 0 <= score <= 10
        # CVSSスコアと緊急度の整合性
        expected_sev = "critical" if score >= 9.0 else "high" if score >= 7.0 else "medium"
        assert item["severity"] == expected_sev
        assert re.match(r"^\d{4}-\d{2}-\d{2}$", item["published_date"])
        assert re.match(r"^https?://", item["source_url"])
        assert isinstance(item["summary_3lines"], list) and len(item["summary_3lines"]) == 3
        for key in ("id", "cve_id", "title", "affected_versions", "recommended_action"):
            assert isinstance(item[key], str) and item[key]
        assert all(isinstance(s, str) and s for s in item["summary_3lines"])

    ids = [i["id"] for i in dataset["items"]]
    assert len(ids) == len(set(ids)), "IDが重複しています"


def _assert_sorted(items: list[dict]) -> None:
    order = {"critical": 0, "high": 1, "medium": 2}
    keys = [(order[i["severity"]], -i["cvss_score"]) for i in items]
    assert keys == sorted(keys)


# --- キュレーション（フォールバック）データ ----------------------------------


def test_curated_fallback_items_count_and_balance(fv):
    items = fv.get_curated_fallback_items("2026-11-24")
    assert 8 <= len(items) <= 10  # SPEC: 8〜10件
    cats = {c: sum(1 for i in items if i["category"] == c) for c in ("Java", "PHP", "Middleware")}
    assert all(n >= 2 for n in cats.values()), cats
    assert {i["severity"] for i in items} == {"critical", "high", "medium"}


def test_build_dataset_fallback_when_network_unavailable(fv, monkeypatch):
    monkeypatch.setattr(fv, "fetch_live_jvn_items", lambda _d: [])
    dataset = fv.build_dataset()
    assert dataset["source_mode"] == "curated_fallback"
    assert_spec_schema(dataset)
    _assert_sorted(dataset["items"])
    assert len(dataset["items"]) == len(fv.get_curated_fallback_items("2026-11-24"))


def test_build_dataset_fallback_when_fetch_raises_internally(fv, monkeypatch):
    """conftest で urlopen 自体が例外を投げる状態（＝ネットワーク遮断）でも出力できること。"""
    dataset = fv.build_dataset()
    assert dataset["source_mode"] == "curated_fallback"
    assert_spec_schema(dataset)


def test_build_dataset_mixes_live_and_curated(fv, monkeypatch):
    raw = fv.parse_jvn_xml(
        build_rdf(
            rdf_item()
            + rdf_item(
                title="Spring Framework における認証回避の脆弱性",
                description="Spring Framework 6.1.0 から 6.1.14",
                identifier="JVNDB-2026-000002",
                references='<sec:references source="CVE" id="CVE-2026-22222"/>',
                cvss='<sec:cvss score="7.5" version="3.1"/>',
            )
        ),
        "2026-11-24",
    )
    monkeypatch.setattr(fv, "fetch_live_jvn_items", lambda _d: raw)
    dataset = fv.build_dataset()
    assert dataset["source_mode"] == "live_and_curated"
    assert_spec_schema(dataset)
    assert len(dataset["items"]) <= 10
    ids = {i["id"] for i in dataset["items"]}
    assert {"JVNDB-2026-000001", "JVNDB-2026-000002"} <= ids
    _assert_sorted(dataset["items"])


def test_build_dataset_survives_triage_failure(fv, monkeypatch):
    raw = fv.parse_jvn_xml(build_rdf(rdf_item()), "2026-11-24")
    monkeypatch.setattr(fv, "fetch_live_jvn_items", lambda _d: raw)

    def broken(_item):
        raise KeyError("unexpected")

    monkeypatch.setattr(fv, "triage_item", broken)
    dataset = fv.build_dataset()
    # ライブ全件が変換失敗した場合はフォールバックへ切り替わる
    assert dataset["source_mode"] == "curated_fallback"
    assert_spec_schema(dataset)


# --- write_dataset -----------------------------------------------------------


def test_write_dataset_outputs_strict_utf8_json(fv, monkeypatch, tmp_path):
    monkeypatch.setattr(fv, "fetch_live_jvn_items", lambda _d: [])
    out = tmp_path / "data" / "vulnerabilities.json"
    fv.write_dataset(fv.build_dataset(), out)

    text = out.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert "緊急" in text  # ensure_ascii=False で日本語がそのまま出力される
    assert '\n  "items"' in text  # インデント付き
    loaded = json.loads(text, parse_constant=_reject_constant)
    assert_spec_schema(loaded)
    assert not list(out.parent.glob("*.tmp")), "一時ファイルが残っています"


def test_write_dataset_rejects_nan_and_keeps_previous_file(fv, tmp_path):
    out = tmp_path / "vulnerabilities.json"
    out.write_text('{"previous": true}\n', encoding="utf-8")
    with pytest.raises(ValueError):
        fv.write_dataset({"items": [{"cvss_score": float("nan")}]}, out)
    # 不正データで既存の正常ファイルが壊されないこと
    assert json.loads(out.read_text(encoding="utf-8")) == {"previous": True}
    assert not list(tmp_path.glob("*.tmp"))


def test_main_writes_fallback_file(fv, monkeypatch, tmp_path):
    out = tmp_path / "vulnerabilities.json"
    monkeypatch.setattr(fv, "OUTPUT_PATH", out)
    monkeypatch.setattr(fv, "load_dotenv", lambda *a, **k: None)
    assert fv.main() == 0
    assert_spec_schema(json.loads(out.read_text(encoding="utf-8"), parse_constant=_reject_constant))


def test_committed_public_json_conforms_to_spec():
    path = PROJECT_ROOT / "public" / "data" / "vulnerabilities.json"
    data = json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=_reject_constant)
    assert_spec_schema(data)


# --- .env 読み込み -----------------------------------------------------------


def test_load_dotenv_does_not_override_existing_env(fv, monkeypatch, tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        '# comment\nexport GEMINI_API_KEY="from-file"\nANTHROPIC_API_KEY=\'quoted\'\nINVALID_LINE\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("GEMINI_API_KEY", "from-env")
    fv.load_dotenv(env)
    import os

    assert os.environ["GEMINI_API_KEY"] == "from-env"
    assert os.environ["ANTHROPIC_API_KEY"] == "quoted"

"""CVSSスコアからの緊急度判定・カテゴリ分類・ルールベーストリアージのテスト。"""

from __future__ import annotations

import math

import pytest


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (10.0, ("critical", "緊急")),
        (9.8, ("critical", "緊急")),
        (9.0, ("critical", "緊急")),  # 境界: 9.0以上は緊急
        (8.9, ("high", "重要")),
        (7.0, ("high", "重要")),  # 境界: 7.0以上は重要
        (6.9, ("medium", "注意")),
        (4.0, ("medium", "注意")),
        (0.0, ("medium", "注意")),  # SPEC値域は3値のため4.0未満も注意に寄せる
        ("9.1", ("critical", "緊急")),  # 文字列表現も受け付ける
    ],
)
def test_classify_severity_boundaries(fv, score, expected):
    assert fv.classify_severity(score) == expected


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf, -1.0, 10.1, None, "abc", True])
def test_classify_severity_invalid_values_fall_back_to_medium(fv, bad):
    assert fv.classify_severity(bad) == ("medium", "注意")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("9.8", 9.8),
        ("7.46", 7.5),  # 小数1桁へ丸める
        (" 5 ", 5.0),
        ("0", 0.0),
        ("10.0", 10.0),
        ("NaN", None),
        ("Infinity", None),
        ("-0.1", None),
        ("10.5", None),
        ("", None),
        (None, None),
        ("high", None),
    ],
)
def test_parse_cvss_value(fv, raw, expected):
    assert fv.parse_cvss_value(raw) == expected


@pytest.mark.parametrize(
    ("title", "desc", "cpes", "expected"),
    [
        ("WordPress 用プラグインにおけるXSS", "PHP製CMS", [], "Middleware"),  # WordPressはPHPより優先
        ("PHP における脆弱性", "", [], "PHP"),
        ("Spring Boot における脆弱性", "", [], "Java"),
        ("Apache Tomcat における脆弱性", "", [], "Java"),
        ("Oracle Java SE の脆弱性", "", [], "Java"),
        ("JavaScript ライブラリにおける脆弱性", "", [], "Middleware"),  # JavaScript は Java ではない
        ("nginx における脆弱性", "", [], "Middleware"),
        ("ある製品の脆弱性", "", [{"vendor": "php", "product": "php"}], "PHP"),
    ],
)
def test_classify_category(fv, title, desc, cpes, expected):
    assert fv.classify_category(title, desc, cpes) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("OpenJDK の脆弱性", True),
        ("Java SE", True),
        ("java.lang の問題", True),
        ("JavaScript エンジンの脆弱性", False),
        ("Apache HTTP Server", True),
        ("Microsoft Exchange Server", False),
    ],
)
def test_matches_target_keywords(fv, text, expected):
    assert fv.matches_target_keywords(text) is expected


def _raw_item(**overrides):
    base = {
        "id": "JVNDB-2026-000001",
        "cve_id": "CVE-2026-11111",
        "raw_title": "PHP における任意のコードを実行される脆弱性",
        "raw_description": "PHP 8.2.0 から 8.2.24 には任意のコードを実行される脆弱性が存在します。",
        "category": "PHP",
        "severity": "critical",
        "severity_label": "緊急",
        "cvss_score": 9.8,
        "published_date": "2026-11-20",
        "cpes": [{"vendor": "php", "product": "php"}],
        "cwes": [],
        "source_url": "https://jvndb.jvn.jp/",
    }
    base.update(overrides)
    return base


def test_triage_with_rules_produces_spec_shape(fv):
    result = fv.triage_with_rules(_raw_item())
    assert set(result) == {"title", "affected_versions", "summary_3lines", "recommended_action"}
    assert len(result["summary_3lines"]) == 3
    assert all(isinstance(s, str) and s for s in result["summary_3lines"])
    # コード実行系キーワード → 該当の危険説明、critical → 最優先の文言
    assert "任意のプログラムを実行" in result["summary_3lines"][0]
    assert "最優先" in result["summary_3lines"][2]
    assert "直ちに" in result["recommended_action"]
    # 影響バージョンが説明文の範囲表記から抽出される
    assert "8.2.0 から 8.2.24" in result["affected_versions"]


@pytest.mark.parametrize(
    ("severity", "score", "keyword"),
    [("high", 8.1, "前倒し"), ("medium", 5.0, "定期メンテナンス")],
)
def test_triage_with_rules_severity_wording(fv, severity, score, keyword):
    result = fv.triage_with_rules(_raw_item(severity=severity, cvss_score=score))
    assert keyword in result["summary_3lines"][2]


def test_triage_with_rules_shortens_long_title(fv):
    long_title = "PHP " + "非常に長いタイトル" * 10
    result = fv.triage_with_rules(_raw_item(raw_title=long_title))
    assert result["title"] == "PHP における脆弱性（CVE-2026-11111）"


def test_sort_items_by_priority(fv):
    items = [
        {"id": "a", "severity": "medium", "cvss_score": 6.0, "published_date": "2026-11-23"},
        {"id": "b", "severity": "critical", "cvss_score": 9.1, "published_date": "2026-11-01"},
        {"id": "c", "severity": "critical", "cvss_score": 9.8, "published_date": "2026-11-01"},
        {"id": "d", "severity": "high", "cvss_score": 7.5, "published_date": "2026-11-20"},
    ]
    assert [i["id"] for i in fv.sort_items_by_priority(items)] == ["c", "b", "d", "a"]

"""pytest 共通設定: scripts/ をインポート可能にし、テスト中の外部通信とAPIキー利用を遮断する。"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import fetch_vulns  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """全テストで実ネットワーク接続と実APIキーの使用を禁止する。"""

    def _blocked_urlopen(*_args, **_kwargs):
        raise AssertionError("テスト中に実ネットワークへ接続しようとしました")

    monkeypatch.setattr(urllib.request, "urlopen", _blocked_urlopen)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture()
def fv():
    """テスト対象モジュール。"""
    return fetch_vulns


class FakeResponse:
    """urllib.request.urlopen の戻り値を模したレスポンス。"""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, size: int = -1) -> bytes:
        return self._body if size is None or size < 0 else self._body[:size]

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_exc) -> None:
        return None


def build_rdf(items_xml: str) -> bytes:
    """JVNDB形式（RSS 1.0 / RDF）のテスト用XMLを組み立てる。"""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"'
        ' xmlns="http://purl.org/rss/1.0/"'
        ' xmlns:dc="http://purl.org/dc/elements/1.1/"'
        ' xmlns:dcterms="http://purl.org/dc/terms/"'
        ' xmlns:sec="http://jvn.jp/rss/mod_sec/">'
        f"{items_xml}"
        "</rdf:RDF>"
    ).encode("utf-8")


def rdf_item(
    title: str = "PHP における任意のコードを実行される脆弱性",
    description: str = "PHP 8.2.0 から 8.2.24 には脆弱性が存在します。",
    link: str = "https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html",
    identifier: str = "JVNDB-2026-000001",
    issued: str = "2026-11-20T10:00+09:00",
    cvss: str = '<sec:cvss score="9.8" severity="Critical" version="3.0"/>',
    references: str = '<sec:references source="CVE" id="CVE-2026-11111"/>',
    cpes: str = "",
) -> str:
    """テスト用の item 要素を組み立てる（XML特殊文字はエスケープ済み前提）。"""
    return (
        f'<item rdf:about="{link}">'
        f"<title>{title}</title>"
        f"<link>{link}</link>"
        f"<description>{description}</description>"
        f"<sec:identifier>{identifier}</sec:identifier>"
        f"{references}{cpes}{cvss}"
        f"<dcterms:issued>{issued}</dcterms:issued>"
        "</item>"
    )

"""public/app.js の静的セキュリティチェックと、Node.js による純粋関数の検証。"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from conftest import PROJECT_ROOT

APP_JS = PROJECT_ROOT / "public" / "app.js"
INDEX_HTML = PROJECT_ROOT / "public" / "index.html"
JS_CHECK = PROJECT_ROOT / "tests" / "js" / "app_js_check.cjs"


def _strip_js_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    return re.sub(r"(^|\s)//.*$", r"\1", src, flags=re.MULTILINE)


def test_app_js_has_no_dangerous_dom_sinks():
    """AGENTS.md / SPEC.md: innerHTML 等の HTML 文字列挿入APIを使用しないこと。"""
    code = _strip_js_comments(APP_JS.read_text(encoding="utf-8"))
    for pattern in (
        r"\.innerHTML\b",
        r"\.outerHTML\b",
        r"insertAdjacentHTML",
        r"document\.write",
        r"\beval\s*\(",
        r"new\s+Function\s*\(",
        r"setTimeout\s*\(\s*['\"`]",
        r"setInterval\s*\(\s*['\"`]",
    ):
        assert not re.search(pattern, code), f"危険なAPIが使用されています: {pattern}"


def test_external_links_use_noopener():
    code = APP_JS.read_text(encoding="utf-8")
    if 'target = "_blank"' in code:
        assert 'rel = "noopener noreferrer"' in code


def test_index_html_has_csp_and_no_inline_script():
    html = INDEX_HTML.read_text(encoding="utf-8")
    assert 'http-equiv="Content-Security-Policy"' in html
    assert "script-src 'self'" in html
    assert "'unsafe-inline'" not in html
    # src 属性を持たないインラインスクリプトやイベントハンドラ属性が無いこと
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html)
    assert not re.search(r"\son[a-z]+\s*=", html, flags=re.IGNORECASE)


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js が未インストールのためスキップ")
def test_app_js_pure_functions_with_node():
    proc = subprocess.run(
        ["node", str(JS_CHECK), str(APP_JS)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert proc.stdout.startswith("OK")

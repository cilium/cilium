#!/usr/bin/env python3
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0
"""
Build a Lunr search index from a Sphinx dirhtml output directory.

Outputs into <OUTDIR>/_static/lunr/:
  docs.json        – array of {id, url, title, breadcrumb, content, snippet}
  lunr_index.json  – pre-built serialised Lunr index
  manifest.json    – build metadata

Usage:
  python build_lunr_index.py [OUTDIR]

If OUTDIR is not given, the script auto-detects:
  1. $READTHEDOCS_OUTPUT/html   (RTD v2 canonical path)
  2. Documentation/_build/dirhtml  (local Sphinx make)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# HTML parsing – prefer BeautifulSoup, fall back to stdlib html.parser
# ---------------------------------------------------------------------------
try:
    from bs4 import BeautifulSoup, Tag  # type: ignore[import]

    def _make_soup(html: str) -> BeautifulSoup:
        return BeautifulSoup(html, "lxml" if _has_lxml() else "html.parser")

    def _has_lxml() -> bool:
        try:
            import lxml  # noqa: F401
            return True
        except ImportError:
            return False

    USE_BS4 = True

except ImportError:
    from html.parser import HTMLParser

    USE_BS4 = False

    class _SimpleParser(HTMLParser):
        """Minimal HTML → plain-text extractor (stdlib fallback)."""

        # Tags whose content we never want
        _SKIP = {"script", "style", "nav", "footer", "head"}
        # Tags that introduce a block break
        _BLOCK = {"p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "td", "th", "div", "section"}

        def __init__(self) -> None:
            super().__init__()
            self._skip_depth: int = 0
            self._text: list[str] = []
            self._title: str = ""
            self._in_title: bool = False

        def handle_starttag(self, tag: str, attrs: list) -> None:  # type: ignore[override]
            if tag in self._SKIP:
                self._skip_depth += 1
            if tag == "title":
                self._in_title = True
            if tag in self._BLOCK and self._text and self._text[-1] != "\n":
                self._text.append("\n")

        def handle_endtag(self, tag: str) -> None:  # type: ignore[override]
            if tag in self._SKIP:
                self._skip_depth = max(0, self._skip_depth - 1)
            if tag == "title":
                self._in_title = False

        def handle_data(self, data: str) -> None:
            if self._skip_depth > 0:
                return
            if self._in_title:
                self._title = data.strip()
                return
            self._text.append(data)

        @property
        def text(self) -> str:
            return re.sub(r"\s+", " ", "".join(self._text)).strip()

        @property
        def title(self) -> str:
            return self._title

    def _make_soup(html: str) -> "_SimpleParser":  # type: ignore[misc]
        p = _SimpleParser()
        p.feed(html)
        return p


# ---------------------------------------------------------------------------
# Content extraction helpers
# ---------------------------------------------------------------------------

_STRIP_ROLES = re.compile(r":\w+:`([^`]*)`")
_STRIP_RST = re.compile(r"\*+([^*]+)\*+")
_WHITESPACE = re.compile(r"\s+")

# Selectors we remove from page text to exclude chrome
_CHROME_SELECTORS = [
    "nav",
    "footer",
    ".wy-nav-side",
    ".wy-nav-top",
    ".rst-versions",
    ".headerlink",
    "script",
    "style",
    ".sphinxsidebar",
    "#searchbox",
    ".admonition-title",
]


def _extract_bs4(html: str, rel_url: str) -> dict:
    """Extract structured data using BeautifulSoup."""
    soup = _make_soup(html)

    # Remove pure-chrome elements
    for sel in _CHROME_SELECTORS:
        for el in soup.select(sel):
            el.decompose()

    # Title: prefer <title> tag, fall back to first h1
    page_title = ""
    title_tag = soup.find("title")
    if title_tag:
        raw = title_tag.get_text(" ", strip=True)
        # "Page Title — Cilium …" → keep only the first part
        page_title = raw.split("—")[0].split("–")[0].strip()

    if not page_title:
        h1 = soup.find("h1")
        if h1:
            page_title = h1.get_text(" ", strip=True)

    # Breadcrumb: RTD theme places .wy-breadcrumbs / .breadcrumbs
    breadcrumb = ""
    bc_tag = soup.select_one(".wy-breadcrumbs, nav.breadcrumbs, ol.breadcrumb")
    if bc_tag:
        parts = [a.get_text(" ", strip=True) for a in bc_tag.find_all("a")]
        if parts:
            breadcrumb = " > ".join(parts)

    # Main content area
    main = (
        soup.select_one("div[role='main']")
        or soup.select_one(".document")
        or soup.select_one("article")
        or soup.find("body")
    )
    content = _WHITESPACE.sub(" ", main.get_text(" ", strip=True)).strip() if main else ""

    snippet = content[:300].rstrip()
    if len(content) > 300:
        snippet += "…"

    return {
        "url": rel_url,
        "title": page_title,
        "breadcrumb": breadcrumb,
        "content": content,
        "snippet": snippet,
    }


def _extract_stdlib(html: str, rel_url: str) -> dict:
    """Extract structured data using stdlib html.parser fallback."""
    parser = _make_soup(html)
    content = parser.text
    title = parser.title.split("—")[0].split("–")[0].strip()
    snippet = content[:300].rstrip()
    if len(content) > 300:
        snippet += "…"
    return {
        "url": rel_url,
        "title": title,
        "breadcrumb": "",
        "content": content,
        "snippet": snippet,
    }


def extract_page(html: str, rel_url: str) -> dict:
    if USE_BS4:
        return _extract_bs4(html, rel_url)
    return _extract_stdlib(html, rel_url)


# ---------------------------------------------------------------------------
# Lunr index builder (pure-Python serialisation)
# ---------------------------------------------------------------------------

def _tokenize(text: str) -> list[str]:
    """Very simple tokeniser – split on non-word characters, lowercase."""
    return [t.lower() for t in re.split(r"\W+", text) if t]


# Porter stemmer suffix rules (a minimal subset sufficient for English docs)
_STOP_WORDS: set[str] = {
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "that", "this",
    "it", "its", "not", "no",
}


def build_lunr_index(docs: list[dict]) -> dict:
    """
    Build a serialised Lunr-compatible index as a plain Python dict.

    We emit a format that matches lunr.Index.load() in Lunr.js 2.x:
    https://lunrjs.com/docs/lunr.Index.html
    """
    import lunr  # type: ignore[import]

    documents = [
        {
            "id": str(doc["id"]),
            "title": doc["title"],
            "content": doc["content"],
        }
        for doc in docs
    ]

    idx = lunr.lunr(
        ref="id",
        fields=[
            {"field_name": "title", "boost": 10},
            {"field_name": "content"},
        ],
        documents=documents,
    )
    return idx.serialize()


def build_lunr_index_js_compat(docs: list[dict]) -> dict:
    """
    Fallback: build a minimal inverted index that lunr-search.js can load
    when the Python `lunr` package is not available.

    The JS side detects the `_format` field and falls back to a client-side
    build using the pre-serialised docs store.
    """
    inverted: dict[str, dict[str, list[int]]] = {}
    for doc in docs:
        doc_id = str(doc["id"])
        tokens = set(_tokenize(doc["title"]) + _tokenize(doc["content"]))
        for token in tokens:
            if token in _STOP_WORDS or len(token) < 2:
                continue
            inverted.setdefault(token, {})[doc_id] = []

    return {
        "_format": "simple-inverted",
        "version": "1.0",
        "inverted": inverted,
    }


# ---------------------------------------------------------------------------
# Directory discovery
# ---------------------------------------------------------------------------

def detect_output_dir(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)

    # RTD v2 sets READTHEDOCS_OUTPUT; HTML lives under html/ inside it
    rtd_output = os.environ.get("READTHEDOCS_OUTPUT")
    if rtd_output:
        candidate = Path(rtd_output) / "html"
        if candidate.is_dir():
            return candidate
        # Some RTD configurations keep files directly in READTHEDOCS_OUTPUT
        return Path(rtd_output)

    # Local Sphinx make dirhtml
    script_dir = Path(__file__).resolve().parent  # Documentation/_scripts/
    docs_dir = script_dir.parent  # Documentation/
    local = docs_dir / "_build" / "dirhtml"
    if local.is_dir():
        return local

    sys.exit(
        "Cannot detect output directory. "
        "Pass it as the first argument or set READTHEDOCS_OUTPUT."
    )


def _url_from_relpath(rel_path: Path) -> str:
    """Convert a relative HTML file path into a URL path for search results."""
    rel_posix = str(rel_path).replace(os.sep, "/")

    # dirhtml pages are emitted as */index.html and should map to */
    if rel_posix == "index.html":
        return ""
    if rel_posix.endswith("/index.html"):
        return rel_posix[: -len("index.html")]

    # html builder pages are emitted as *.html and should keep extension
    return rel_posix


def iter_html_files(outdir: Path):
    """Yield (html_path, relative_url) pairs for Sphinx html or dirhtml output."""
    yielded: set[Path] = set()

    # dirhtml layout: */index.html files
    for html_file in sorted(outdir.rglob("*/index.html")):
        rel_path = html_file.relative_to(outdir)
        yielded.add(rel_path)
        yield html_file, _url_from_relpath(rel_path)

    # html layout: *.html files at root and nested directories
    for html_file in sorted(outdir.rglob("*.html")):
        rel_path = html_file.relative_to(outdir)
        if rel_path in yielded:
            continue
        yield html_file, _url_from_relpath(rel_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "outdir",
        nargs="?",
        help="Path to the built HTML output directory (auto-detected if omitted).",
    )
    args = parser.parse_args()

    outdir = detect_output_dir(args.outdir)
    print(f"[lunr-index] Using output dir: {outdir}", flush=True)

    static_lunr = outdir / "_static" / "lunr"
    static_lunr.mkdir(parents=True, exist_ok=True)

    docs: list[dict] = []
    seen_urls: set[str] = set()

    for idx, (html_file, rel_url) in enumerate(iter_html_files(outdir)):
        if rel_url in seen_urls:
            continue
        seen_urls.add(rel_url)

        try:
            raw_html = html_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"[lunr-index] WARNING: cannot read {html_file}: {exc}", file=sys.stderr)
            continue

        page = extract_page(raw_html, rel_url)
        if not page["title"] and not page["content"]:
            continue  # skip empty/non-content pages

        page["id"] = idx
        docs.append(page)

    print(f"[lunr-index] Indexed {len(docs)} pages.", flush=True)

    # Write docs store (title, breadcrumb, snippet, url – no full content)
    docs_store = [
        {
            "id": d["id"],
            "url": d["url"],
            "title": d["title"],
            "breadcrumb": d["breadcrumb"],
            "snippet": d["snippet"],
        }
        for d in docs
    ]
    (static_lunr / "docs.json").write_text(
        json.dumps(docs_store, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    print(f"[lunr-index] Written {static_lunr / 'docs.json'}", flush=True)

    # Write Lunr index
    try:
        lunr_index = build_lunr_index(docs)
        index_type = "lunr-serialised"
    except ImportError:
        print(
            "[lunr-index] WARNING: Python `lunr` package not available; "
            "writing simple inverted index (client-side Lunr build will be used).",
            file=sys.stderr,
        )
        lunr_index = build_lunr_index_js_compat(docs)
        index_type = "simple-inverted"

    (static_lunr / "lunr_index.json").write_text(
        json.dumps(lunr_index, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    print(f"[lunr-index] Written {static_lunr / 'lunr_index.json'} ({index_type})", flush=True)

    # Write manifest
    manifest = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "page_count": len(docs),
        "index_type": index_type,
        "parser": "beautifulsoup4" if USE_BS4 else "stdlib-html.parser",
    }
    (static_lunr / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[lunr-index] Written {static_lunr / 'manifest.json'}", flush=True)


if __name__ == "__main__":
    main()

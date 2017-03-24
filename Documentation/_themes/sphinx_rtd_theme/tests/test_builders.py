import os

import pytest
import sphinx
from sphinx import addnodes
from sphinx.builders.html import SingleFileHTMLBuilder, DirectoryHTMLBuilder

from .util import build_all


def test_basic():
    for (app, status, warning) in build_all('test-basic'):
        assert app.env.get_doctree('index').traverse(addnodes.toctree)
        content = open(os.path.join(app.outdir, 'index.html')).read()

        if isinstance(app.builder, DirectoryHTMLBuilder):
            search = (
                '<div class="toctree-wrapper compound">\n'
                '<ul>\n'
                '<li class="toctree-l1">'
                '<a class="reference internal" href="foo/">foo</a>'
                '<ul>\n'
                '<li class="toctree-l2">'
                '<a class="reference internal" href="bar/">bar</a></li>\n'
                '</ul>\n'
                '</li>\n'
                '</ul>\n'
                '</div>'
            )
            assert search in content
        elif isinstance(app.builder, SingleFileHTMLBuilder):
            search = (
                '<div class="local-toc"><ul>\n'
                '<li class="toctree-l1">'
                '<a class="reference internal" href="index.html#document-foo">foo</a>'
                '<ul>\n'
                '<li class="toctree-l2">'
                '<a class="reference internal" href="index.html#document-bar">bar</a>'
                '</li>\n'
                '</ul>'
            )
            assert search in content
        else:
            search = (
                '<div class="toctree-wrapper compound">\n'
                '<ul>\n'
                '<li class="toctree-l1">'
                '<a class="reference internal" href="foo.html">foo</a>'
                '<ul>\n'
                '<li class="toctree-l2">'
                '<a class="reference internal" href="bar.html">bar</a></li>\n'
                '</ul>\n'
                '</li>\n'
                '</ul>\n'
                '</div>'
            )
            assert search in content, ('Missing search with builder {0}'
                                       .format(app.builder.name))


def test_empty():
    """Local TOC is showing, as toctree was empty"""
    for (app, status, warning) in build_all('test-empty'):
        assert app.env.get_doctree('index').traverse(addnodes.toctree)
        content = open(os.path.join(app.outdir, 'index.html')).read()
        if sphinx.version_info < (1, 4):
            if isinstance(app.builder, SingleFileHTMLBuilder):
                assert '<div class="toctree-wrapper compound">\n</div>' in content
                assert '<div class="local-toc">' in content
            else:
                global_toc = (
                    '<div class="toctree-wrapper compound">\n'
                    '<ul class="simple">\n</ul>\n'
                    '</div>'
                )
                local_toc = (
                    '<div class="local-toc"><ul class="simple">'
                    '</ul>\n</div>'
                )
                assert global_toc in content
                assert local_toc not in content
        else:
            global_toc = '<div class="toctree-wrapper compound">\n</div>'
            local_toc = (
                '<div class="local-toc"><ul>\n'
                '<li><a class="reference internal" href="#">test-empty</a></li>'
                '</ul>\n</div>'
            )
            assert global_toc in content
            assert local_toc not in content


def test_missing_toctree():
    """Local TOC is showing, as toctree was missing"""
    for (app, status, warning) in build_all('test-missing-toctree'):
        assert app.env.get_doctree('index').traverse(addnodes.toctree) == []
        content = open(os.path.join(app.outdir, 'index.html')).read()
        assert '<div class="toctree' not in content
        assert '<div class="local-toc">' in content

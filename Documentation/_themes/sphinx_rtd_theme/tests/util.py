from __future__ import print_function

import os
import tempfile
import shutil
from contextlib import contextmanager

import pytest
from sphinx.application import Sphinx

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


@contextmanager
def build(root, builder='html', **kwargs):
    tmpdir = tempfile.mkdtemp()

    srcdir = os.path.join(os.path.dirname(__file__), 'roots', root)
    destdir = os.path.join(tmpdir, builder)
    doctreedir = os.path.join(tmpdir, 'doctree/')

    status = StringIO()
    warning = StringIO()

    kwargs.update({
        'status': status,
        'warning': warning,
    })

    confoverrides = kwargs.pop('confoverrides', {})
    confoverrides['html_theme'] = 'sphinx_rtd_theme'
    extensions = confoverrides.get('extensions', [])
    extensions.append('readthedocs_ext.readthedocs')
    confoverrides['extensions'] = extensions
    kwargs['confoverrides'] = confoverrides

    try:
        app = Sphinx(srcdir, srcdir, destdir, doctreedir, builder, **kwargs)
        app.builder.build_all()
        yield (app, status.getvalue(), warning.getvalue())
    except Exception as e:
        print('# root:', root)
        print('# builder:', builder)
        print('# source:', srcdir)
        print('# destination:', destdir)
        print('# status:', '\n' + status.getvalue())
        print('# warning:', '\n' + warning.getvalue())
        raise
    finally:
        shutil.rmtree(tmpdir)


def build_all(root, **kwargs):
    for builder in ['html', 'singlehtml', 'readthedocs', 'readthedocsdirhtml',
                    'readthedocssinglehtml', 'readthedocssinglehtmllocalmedia']:
        with build(root, builder, **kwargs) as ret:
            yield ret

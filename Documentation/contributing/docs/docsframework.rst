.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _docs_framework:

***********************
Documentation framework
***********************

This page contains notes on the framework in use for Cilium documentation. Its
objective is to help contributors understand the tools and build process for
the documentation, and to help maintain it.

Alas, this sort of document goes quickly out of date. When in doubt of
accuracy, double-check the codebase to verify information. If you find
discrepancies, please update this page.

Sphinx
======

Cilium relies on `Sphinx`_ to generate its documentation.

.. _Sphinx: https://www.sphinx-doc.org

Sphinx usage
------------

Contributors do not usually call Sphinx directly, but rather use the Makefile
targets defined in ``Documentation/Makefile``. For instructions on how to
quickly render the documentation, see :ref:`testing documentation
<testing-documentation>`.

Sphinx features
---------------

Here are some specific Sphinx features used in Cilium's documentation:

- `Tab groups`_

- `OpenAPI`_ documentation generation

- Mark-up languages: reStructuredText (rST) and Markdown (`MyST`_ flavor)

- Substitutions, for example:

  - ``|SCM_WEB|``
  - ``|CHART_VERSION|``

- Multiple versions (for all supported branches, plus two aliases: ``stable``
  and ``latest``)

.. _OpenAPI: https://github.com/sphinx-contrib/openapi
.. _Tab groups: https://github.com/executablebooks/sphinx-tabs/
.. _MyST: https://myst-parser.readthedocs.io

Sphinx version
--------------

The version of Sphinx in use is defined in
``Documentation/requirements-min/requirements.txt``. For more details, see the
:ref:`section on requirements <docs_requirements>`.

Auto-generated contents
=======================

Some contents are automatically generated at build time. File
``Documentation/Makefile`` contains the following target, shown here in a
simplified version, which regenerates a number of documents and then checks
that they are all up-to-date:

.. code-block:: makefile

   check: builder-image api-flaggen update-cmdref update-crdlist update-helm-values update-codeowners update-redirects
     ./check-cmdref.sh
     ./check-helmvalues.sh
     $(DOCKER_RUN) ./check-examples.sh # Runs "cilium policy validate" and "yamllint"
     ./check-codeowners.sh
     ./check-flaggen.sh
     ./check-crdlist.sh
     ./check-redirects.sh

Regeneration happens when the different dependency targets for ``check`` are
run. They are:

- ``api-flaggen``

  - Runs ``go run tools/apiflaggen``
  - Generates ``Documentation/configuration/api-restrictions-table.rst``

- ``update-cmdref``

  - Runs ``./update-cmdref.sh``
  - Includes running various binaries with ``--cmdref``
  - Generates ``Documentation/cmdref/\*``

- ``update-crdlist``

  - ``make -C ../ generate-crd-docs``
  - Runs ``tools/crdlistgen/main.go``
  - Parses docs to list CRDs
  - Generates ``Documentation/crdlist.rst``

- ``update-helm-values``

  - Generates from ``install/kubernetes``
  - Generates ``Documentation/helm-values.rst``

- ``update-codeowners``

  - ``./update-codeowners.sh``
  - Synchronizes teams description from ``CODEOWNERS``
  - Generates ``Documentation/codeowners.rst``

- ``update-redirects``

  - ``make -C Documentation update-redirects``
  - Automatically generates redirects based on moved files based on git history.
  - Validates that all moved or deleted files have a redirect.
  - Generates ``Documentation/redirects.txt``

Other auto-generated contents include:

- OpenAPI reference

  - YAML generated from the ``Makefile`` at the root of the repository
  - Relies on the contents of ``api``, linked as ``Documentation/_api``
  - Processed and included via a dedicated add-on, from
    ``Documentation/api.rst``: ``.. openapi:: ../api/v1/openapi.yaml``

- gRPC API reference

  - Markdown generated from the main ``Makefile`` at the root of the repository
  - Relies on the contents of ``api``, linked as ``Documentation/_api``
  - Included from ``Documentation/grpcapi.rst``

Build system
============

Makefile targets
----------------

Here are the main ``Makefile`` targets related to documentation to run from the
root of the Cilium repository, as well as some indications on what they call:

- ``make`` -> ``all: ... postcheck`` -> ``make -C Documentation check``:
  Build Cilium and validate the documentation via the ``postcheck`` target
- ``make -C Documentation html``:
  Render the documentation as HTML
- ``make test-docs`` -> ``make -C Documentation html``:
  Render the documentation as HTML
- ``make -C Documentation live-preview``:
  Build the documentation and start a server for local preview
- ``make render-docs`` -> ``make -C Documentation live-preview``:
  Build the documentation and start a server for local preview

Generating documentation
------------------------

- The ``Makefile`` builds the documentation using the ``docs-builder`` Docker
  image.

- The build includes running ``check-build.sh``. This script:

  a. Runs the linter (``rstcheck``), unless the environment variable
     ``SKIP_LINT`` is set
  b. Runs the spell checker
  c. Builds the HTML version of the documentation
  d. Exits with an error if any unexpected warning or error is found

Tweaks and tools
================

See also file ``Documentation/conf.py``.

Spell checker
-------------

The build system relies on Sphinx's `spell-checker module`_ (considered a
`builder`_ in Sphinx).

The spell checker uses a list of known exceptions contained in
``Documentation/spelling_wordlist.txt``. Words in the list that are written
with lowercase exclusively, or uppercase exclusively, are case-insensitive
exceptions for spell-checking. Words with mixed case are case-sensitive. Keep
this file sorted alphabetically.

To add new entries to the list, run ``Documentation/update-spelling_wordlist.sh``.

To clean-up obsolete entries, first make sure the spell checker reports no
issue on the current version of the documentation. Then remove all obsolete
entries from the file, run the spell checker, and re-add all reported
exceptions.

Cilium's build framework uses a custom filter for the spell checker, for
spelling ``WireGuard`` correctly as ``WireGuard``, or ``wireguard`` in some
contexts, but never as ``Wireguard``. This filter is implemented in
``Documentation/_exts/cilium_spellfilters.py`` and registered in
``Documentation/conf.py``.

.. _spell-checker module: https://github.com/sphinx-contrib/spelling
.. _builder: https://www.sphinx-doc.org/en/master/usage/builders

Redirect checker/builder
------------------------

The build system relies on the Sphinx extension `sphinxext-rediraffe`_ (considered a
`builder`_ in Sphinx) for redirects.

The redirect checker uses the git history to determine if a file has been moved or deleted in order to validate that a redirect for the file has been created in ``Documentation/redirects.txt``.
Redirects are defined as a mapping from the original source file location to the new location within the ``Documentation/`` directory. The extension uses the ``rediraffe_branch`` as the git ref to diff against to determine which files have been moved or deleted. Any changes prior to the ref specified by ``rediraffe_branch`` will not be detected.

To add new entries to the ``redirects.txt``, run ``make -C Documentation update-redirects``.

If a file has been deleted, or has been moved and is not similar enough to the original source file, then you must manually update ``redirects.txt`` with the correct mapping.

.. _sphinxext-rediraffe: https://github.com/wpilibsuite/sphinxext-rediraffe

:spelling:word:`rstcheck`
-------------------------

The documentation framework relies on `rstcheck`_ to validate the rST
formatting. There is a list of warnings to ignore, in part because the linter
has bugs. The call to the tool, and this list of exceptions, are configured in
``Documentation/check-build.sh``.

.. _rstcheck: https://rstcheck.readthedocs.io

Link checker
------------

The documentation framework has a link checker under
``Documentation/check-links.sh``. However, due to some unsolved issues, it does
not run in CI. See :gh-issue:`27116` for details.

Web server for local preview
----------------------------

Launch a web server to preview the generated documentation locally with ``make
render-docs``.

For more information on this topic, see :ref:`testing documentation
<testing-documentation>`.

Custom Sphinx roles
-------------------

The documentation defines several custom roles:

- ``git-tree``
- ``github-project``
- ``github-backport``
- ``gh-issue``
- ``prev-docs``

Calling these roles helps insert links based on specific URL templates, via the
`extlinks`_ extension. They are all configured in ``Documentation/conf.py``.
They should be used wherever relevant, to ensure that formatting for all links
to the related resources remain consistent.

.. _extlinks: https://www.sphinx-doc.org/en/master/usage/extensions/extlinks.html

Custom Sphinx directives
------------------------

Cilium's documentation does not implement custom directives as of this writing.

Custom extensions
-----------------

Cilium's documentation uses custom extensions for Sphinx, implemented under
``Documentation/_exts``.

- One defines the custom filters for the spell checker.
- One patches Sphinx's HTML translator to open all external links in new tabs.

Google Analytics
----------------

The documentation uses Google Analytics to collect metrics. This is configured
in ``Documentation/conf.py``.

Customization
-------------

Here are additional elements of customization for Cilium's documentation
defined in the main repository:

- Some custom CSS; see also class ``wrapped-table`` in the related CSS file
  ``Documentation/_static/wrapped-table.css``

- A "Copy" button, including a button to copy only commands from console-code
  blocks, implemented in ``Documentation/_static/copybutton.js`` and
  ``Documentation/_static/copybutton.css``

- Custom header and footer definitions, for example to make link to Slack
  target available on all pages

- Warning banner on older branches, telling to check out the latest version
  (these may be handled directly in the ReadTheDocs configuration in the
  future, see also :gh-issue:`29969`)

Algolia search engine
---------------------

- :spelling:word:`Algolia` provides a search engine for the documentation website. See also the
  repository for the `DocSearch scraper`_.

.. _DocSearch scraper: https://github.com/cilium/docsearch-scraper-webhook

Build set up
============

.. _docs_requirements:

Requirements (dependencies)
---------------------------

The repository contains two files for requirements: one that declares and pins
the core dependencies for the documentation build system, and that maintainers
use to generate a second requirement files that includes all sub-dependencies,
via a dedicated Makefile target.

- The base requirements are defined in
  ``Documentation/requirements-min/requirements.txt``.
- Running ``make -C Documentation update-requirements`` uses this file as a
  base to generate ``Documentation/requirements.txt``.

Dependencies defined in ``Documentation/requirements-min/requirements.txt``
should never be updated in ``Documentation/requirements.txt`` directly.
Instead, update the former and regenerate the latter.

File ``Documentation/requirements.txt`` is used to build the ``docs-builder``
Docker image.

Dependencies defined in these requirements files include the documentation's
custom theme.

Docker set-up
-------------

The documentation build system relies on a Docker image, ``docs-builder``, to
ensure the build environment is consistent across different systems. Resources
related to this image include ``Documentation/Dockerfile`` and the requirement
files.

Versions of this image are automatically built and published to a registry when
the Dockerfile or the list of dependencies is updated. This is handled in CI
workflow ``.github/workflows/build-images-docs-builder.yaml``.

If a Pull Request updates the Dockerfile or its dependencies, have someone run
the two-steps deployment described in this workflow to ensure that the CI picks
up an updated image.

ReadTheDocs
-----------

Cilium's documentation is hosted on ReadTheDocs. The main configuration options
are defined in ``Documentation/.readthedocs.yaml``.

Some options, however, are only configurable in the ReadTheDocs web interface.
For example:

- The location of the configuration file in the repository
- Redirects
- Triggers for deployment

Custom theme
============

The online documentation uses a custom theme based on `the ReadTheDocs theme`_.
This theme is defined in its `dedicated sphinx_rtd_theme fork repository`_.

.. _the ReadTheDocs theme: https://github.com/readthedocs/sphinx_rtd_theme
.. _dedicated sphinx_rtd_theme fork repository:
   https://github.com/cilium/sphinx_rtd_theme/

Do not use the ``master`` branch of this repository. The commit or branch to
use is referenced in ``Documentation/requirements.txt``, generated from
``Documentation/requirements-min/requirements.txt``, in the Cilium repository.

CI checks
=========

There are several workflows relating to the documentation in CI:

- Documentation workflow:

  - Defined in ``.github/workflows/documentation.yaml``
  - Tests the build, runs the linter, checks the spelling, ensures auto-generated
    contents are up-to-date
  - Runs ``./Documentation/check-builds.sh html`` from the ``docs-builder``
    image

- Netlify preview:

  - Hook defined at Netlify, configured in Netlify's web interface
  - Checks the build
  - Used for previews on Pull Requests, but *not* for deploying the
    documentation
  - Uses a separate Makefile target (``html-netlify``), runs ``check-build.sh``
    with ``SKIP_LINT=1``

- Runtime tests:

  - In the absence of updates to the Dockerfile or documentation dependencies,
    runtime tests are the only workflow that always rebuilds the
    ``docs-builder`` image before generating the docs.

- Image update workflow:

  - Rebuilds the ``docs-builder`` image, pushes it to Quay.io, and updates the
    image reference with the new one in the documentation workflow
  - Triggers when requirements or ``Documentation/Dockerfile`` are updated
  - Needs approval from one of the ``docs-structure`` team members

Redirects
=========

Some pages change location or name over time. To improve user experience, there
is a set of redirects in place. These redirects are configured from the
ReadTheDocs interface. They are a pain to maintain.

Redirects could possibly be configured from existing, dedicated Sphinx
extensions, but this option would require research to analyze and implement.

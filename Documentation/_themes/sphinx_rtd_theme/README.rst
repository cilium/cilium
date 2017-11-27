.. _readthedocs.org: http://www.readthedocs.org
.. _bower: http://www.bower.io
.. _sphinx: http://www.sphinx-doc.org
.. _compass: http://www.compass-style.org
.. _sass: http://www.sass-lang.com
.. _wyrm: http://www.github.com/snide/wyrm/
.. _grunt: http://www.gruntjs.com
.. _node: http://www.nodejs.com
.. _demo: http://docs.readthedocs.org
.. _hidden: http://sphinx-doc.org/markup/toctree.html

.. image:: https://img.shields.io/pypi/v/sphinx_rtd_theme.svg
   :target: https://pypi.python.org/pypi/sphinx_rtd_theme
.. image:: https://travis-ci.org/rtfd/sphinx_rtd_theme.svg?branch=master
   :target: https://travis-ci.org/rtfd/sphinx_rtd_theme
.. image:: https://img.shields.io/pypi/l/sphinx_rtd_theme.svg
   :target: https://pypi.python.org/pypi/sphinx_rtd_theme/
   :alt: license

**************************
Read the Docs Sphinx Theme
**************************

.. contents:: 

View a working demo_ over on readthedocs.org_.

This is a mobile-friendly sphinx_ theme I made for readthedocs.org_.

If you'd like to update the theme,
please make your edits to the SASS files here,
rather than the .css files on checked into the repo.

.. image:: demo_docs/source/static/screen_mobile.png
    :width: 100%

Installation
============

Via package
-----------

Download the package or add it to your ``requirements.txt`` file:

.. code:: bash

    pip install sphinx_rtd_theme

In your ``conf.py`` file:

.. code:: python

    import sphinx_rtd_theme
    html_theme = "sphinx_rtd_theme"
    html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]

or (since v0.2.5):

.. code:: python

    html_theme = "sphinx_rtd_theme"

Via git or download
-------------------

Symlink or subtree the ``sphinx_rtd_theme/sphinx_rtd_theme`` repository into your documentation at
``docs/_themes/sphinx_rtd_theme`` then add the following two settings to your Sphinx
``conf.py`` file:

.. code:: python

    html_theme = "sphinx_rtd_theme"
    html_theme_path = ["_themes", ]

Configuration
=============

You can configure different parts of the theme.

Project-wide configuration
--------------------------

The theme's project-wide options are defined in the ``sphinx_rtd_theme/theme.conf``
file of this repository, and can be defined in your project's ``conf.py`` via
``html_theme_options``. For example:

.. code:: python

    html_theme_options = {
        'collapse_navigation': False,
        'display_version': False,
        'navigation_depth': 3,
    }

The following options are available:

* ``canonical_url`` This will specify a `canonical url <https://en.wikipedia.org/wiki/Canonical_link_element>`__
  to let search engines know they should give higher ranking to latest version of the docs.
  The url points to the root of the documentation and requires a trailing slash.

Page-level configuration
------------------------

Pages support metadata that changes how the theme renders.
You can currently add the following:

* ``:github_url:`` This will force the "Edit on GitHub" to the configured URL
* ``:bitbucket_url:`` This will force the "Edit on Bitbucket" to the configured URL
* ``:gitlab_url:`` This will force the "Edit on GitLab" to the configured URL

Changelog
=========

master
------

* Include fontawesome-webfont.woff2 in pip package
* Updated wyrm_ and Font Awesome
* Split multiple data types on different lines
* Italicize ``.versionmodified``
* Fix line number spacing to align with the code lines
* Hide Edit links on auto created pages
* Align ``.. centered::`` text to the center
* Increase contrast for footnotes
* Add language to the JS output variable
* Include the lato italics font with the theme
* Fix padding on field lists
* Add setuptools entry point allowing to use ``sphinx_rtd_theme`` as
  Sphinx ``html_theme`` directly.

v0.2.4
------

* Yet another patch to deal with extra builders outside Spinx, such as the
  singlehtml builders from the Read the Docs Sphinx extension

v0.2.3
------

* Temporarily patch Sphinx issue with ``singlehtml`` builder by inspecting the
  builder in template.

v0.2.2
------

* Roll back toctree fix in 0.2.1 (#367). This didn't fix the issue and
  introduced another bug with toctrees display.

v0.2.1
------

* Add the ``rel`` HTML attribute to the footer links which point to
  the previous and next pages.
* Fix toctree issue caused by Sphinx singlehtml builder (#367)

v0.2.0
------

* Adds the ``comments`` block after the ``body`` block in the template
* Added "Edit on GitLab" support
* Many bug fixes

v0.1.10-alpha
-------------

.. note:: This is a pre-release version

* Removes Sphinx dependency
* Fixes hamburger on mobile display
* Adds a ``body_begin`` block to the template
* Add ``prev_next_buttons_location`` which can take the value ``bottom``,
  ``top``, ``both`` , ``None`` and will display the "Next" and "Previous"
  buttons accordingly

v0.1.9
------

* Intermittent scrollbar visibility bug fixed. This change introduces a
  backwards incompatible change to the theme's layout HTML. This should only be
  a problem for derivative themes that have overridden styling of nav elements
  using direct decendant selectors. See `#215`_ for more information.
* Safari overscroll bug fixed
* Version added to the nav header
* Revision id was added to the documentation footer if you are using RTD
* An extra block, ``extrafooter`` was added to allow extra content in the
  document footer block
* Fixed modernizr URL
* Small display style changes on code blocks, figure captions, and nav elements

.. _#215: https://github.com/rtfd/sphinx_rtd_theme/pull/215

v0.1.8
------

* Start keeping changelog :)
* Support for third and fourth level headers in the sidebar
* Add support for Sphinx 1.3
* Add sidebar headers for :caption: in Sphinx toctree
* Clean up sidebar scrolling behavior so it never scrolls out of view

How the Table of Contents builds
================================

Currently the left menu will build based upon any ``toctree(s)`` defined in your ``index.rst`` file.
It outputs 2 levels of depth, which should give your visitors a high level of access to your
docs. If no toctrees are set the theme reverts to sphinx's usual local toctree.

It's important to note that if you don't follow the same styling for your rST headers across
your documents, the toctree will misbuild, and the resulting menu might not show the correct
depth when it renders.

Also note that the table of contents is set with ``includehidden=true``. This allows you
to set a hidden toc in your index file with the hidden_ property that will allow you
to build a toc without it rendering in your index.

By default, the navigation will "stick" to the screen as you scroll. However if your toc
is vertically too large, it will revert to static positioning. To disable the sticky nav
altogether change the setting in ``conf.py``.

Contributing or modifying the theme
===================================

The sphinx_rtd_theme is primarily a sass_ project that requires a few other sass libraries. I'm
using bower_ to manage these dependencies and sass_ to build the css. The good news is
I have a very nice set of grunt_ operations that will not only load these dependencies, but watch
for changes, rebuild the sphinx demo docs and build a distributable version of the theme.
The bad news is this means you'll need to set up your environment similar to that
of a front-end developer (vs. that of a python developer). That means installing node and ruby.

Set up your environment
-----------------------

#. Install sphinx_ into a virtual environment.

   .. code:: bash
   
       pip install sphinx sphinxcontrib-httpdomain

#. Install sass.

   .. code:: bash

       gem install sass

#. Install node, bower, grunt, and theme dependencies.

   .. code:: bash

       # Install node
       brew install node

       # Install bower and grunt
       npm install -g bower grunt-cli

       # Now that everything is installed, let's install the theme dependencies.
       npm install

Now that our environment is set up, make sure you're in your virtual environment, go to
this repository in your terminal and run grunt:

.. code::

    grunt

This default task will do the following **very cool things that make it worth the trouble**:

#. Install and update any bower dependencies.
#. Run sphinx and build new docs.
#. Watch for changes to the sass files and build css from the changes.
#. Rebuild the sphinx docs anytime it notices a change to ``.rst``, ``.html``, ``.js``
   or ``.css`` files.

Before you create an issue
--------------------------

I don't have a lot of time to maintain this project due to other responsibilities.
I know there are a lot of Python engineers out there that can't code sass / css and
are unable to submit pull requests. That said, submitting random style bugs without
at least providing sample documentation that replicates your problem is a good
way for me to ignore your request. RST unfortunately can spit out a lot of things
in a lot of ways. I don't have time to research your problem for you, but I do
have time to fix the actual styling issue if you can replicate the problem for me.

Releasing the Theme
===================

When you release a new version,
you should do the following:

#. Bump the version in ``sphinx_rtd_theme/__init__.py`` – we try to follow `semver <http://semver.org/>`_, so be careful with breaking changes.
#. Run a ``grunt build`` to rebuild all the theme assets.
#. Commit that change.
#. Tag the release in git: ``git tag $NEW_VERSION``.
#. Push the tag to GitHub: ``git push --tags origin``.
#. Upload the package to PyPI: ``python setup.py sdist bdist_wheel upload``.
#. In the ``readthedocs.org`` repo, edit the ``bower.json`` file to point at the correct version (``sphinx-rtd-theme": "https://github.com/rtfd/sphinx-rtd-theme.git#$NEW_VERSION"``).
#. In the ``readthedocs.org`` repo, run ``gulp build`` to update the distributed theme files.

TODO
====

* Separate some sass variables at the theme level so you can overwrite some basic colors.

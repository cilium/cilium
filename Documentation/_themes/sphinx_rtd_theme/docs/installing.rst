
************
Installation
************

Via Python Package
==================

Install the package (or add it to your ``requirements.txt`` file):

.. code:: bash

    pip install sphinx_rtd_theme

In your ``conf.py`` file:

.. code:: python

    html_theme = "sphinx_rtd_theme"

Via Git or Download
===================

Symlink or subtree the ``sphinx_rtd_theme/sphinx_rtd_theme`` repository into your documentation at
``docs/_themes/sphinx_rtd_theme`` then add the following two settings to your Sphinx
``conf.py`` file:

.. code:: python

    html_theme = "sphinx_rtd_theme"
    html_theme_path = ["_themes", ]
 

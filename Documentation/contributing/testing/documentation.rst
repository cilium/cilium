.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _testing-documentation:

Documentation
=============

First, start a local document server that automatically refreshes when you save files for
real-time preview. It relies on the ``cilium/docs-builder`` Docker container.

.. code-block:: shell-session

    $ make render-docs

and preview the documentation at http://localhost:9081/ as you make changes. After making changes to
Cilium documentation you should check that you did not introduce any new warnings or errors, and also
check that your changes look as you intended one last time before opening a pull request. To do this
you can build the docs:

.. code-block:: shell-session

    $ make test-docs

.. note::

   By default, ``render-docs`` generates a preview with instructions to install
   Cilium from the latest version on GitHub (i.e. from the HEAD of the master branch that has
   not been released) regardless of which Cilium branch you are in. You can target a specific
   branch by specifying ``READTHEDOCS_VERSION`` environment variable:

   .. code-block:: shell-session

      READTHEDOCS_VERSION=v1.7 make render-docs

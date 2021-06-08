.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Documentation
=============

First, start a local document server that automatically refreshes when you save files for
real-time preview. It relies on the ``cilium/docs-builder`` Docker container.

.. code-block:: shell-session

    $ make render-docs-live-preview

and preview the documentation at http://localhost:9081/ as you make changes. After making changes to
Cilium documentation you should check that you did not introduce any new warnings or errors, and also
check that your changes look as you intended one last time before opening a pull request. To do this
you can build the docs:

.. code-block:: shell-session

    $ make render-docs

This generates documentation files and starts a web server using a Docker container. You can
view the updated documentation by opening either ``Documentation/_build/html/index.html`` or
http://localhost:9081 in a browser.

.. note::

   By default, ``render-docs-live-preview`` generates a preview with instructions to install
   Cilium from the latest version on GitHub (i.e. from the HEAD of the master branch that has
   not been released) regardless of which Cilium branch you are in. You can target a specific
   branch by specifying ``READTHEDOCS_VERSION`` environment variable:

   .. code-block:: shell-session

      READTHEDOCS_VERSION=v1.7 make render-docs-live-preview

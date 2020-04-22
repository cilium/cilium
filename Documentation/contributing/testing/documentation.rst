.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Documentation
=============

Building
~~~~~~~~

The documentation has several dependencies which can be installed using pip:

::

    $ pip install -r Documentation/requirements.txt

.. note:

   If you are using the vagrant development environment, these requirements are
   usually already installed.

Whenever making changes to Cilium documentation you should check that you did not introduce any new warnings or errors, and also check that your changes look as you intended.  To do this you can build the docs:

::

    $ make -C Documentation html

After this you can browse the updated docs as HTML starting at
``Documentation\_build\html\index.html``.

Alternatively you can use a Docker container to build the pages:

::

    $ make render-docs

This builds the docs in a container and builds and starts a web server with
your document changes.

Now the documentation page should be browsable on http://localhost:9080.

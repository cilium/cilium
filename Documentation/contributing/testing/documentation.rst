.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Documentation
=============

Whenever making changes to Cilium documentation you should check that you did not introduce any new warnings or errors, and also check that your changes look as you intended.  To do this you can build the docs:

::

    $ make render-docs

This generates documentation files and starts a web server using a Docker container. You can
view the updated documentation by opening either ``Documentation/_build/html/index.html`` or
http://localhost:9081 in a browser.

.. note:: ``make render-docs`` is relatively slow since it performs syntax and spelling checks.
          You can run ``make render-docs SKIP_LINT=1`` to render the documentation without performing
          these checks while you iterate on updating the documentation.

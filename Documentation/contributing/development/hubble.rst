.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io


.. _hubble_contributing:

Hubble
======

This section is specific to Hubble contributions.

Bumping the vendored Cilium dependency
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Hubble vendors Cilium using Go modules. You can bump the dependency by first
running:

.. code-block:: shell-session

        go get github.com/cilium/cilium@main

However, Cilium's ``go.mod`` contains ``replace`` directives, which are ignored
by ``go get`` and ``go mod``. Therefore you must also manually copy any updated
``replace`` directives from Cilium's ``go.mod`` to Hubble's ``go.mod``.

Once you have done this you can tidy up, vendor the modules, and verify them:

.. code-block:: shell-session

        go mod tidy
        go mod vendor
        go mod verify

The bumped dependency should be committed as a single commit containing all the
changes to ``go.mod``, ``go.sum``, and the ``vendor`` directory.

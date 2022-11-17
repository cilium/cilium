.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _integration_testing:

Integration Testing
===================

Cilium uses the standard `go test <https://golang.org/pkg/testing/>`__ framework
in combination with `gocheck <http://labix.org/gocheck>`__ for richer testing
functionality.

.. _integration_testing_prerequisites:

Prerequisites
^^^^^^^^^^^^^

Some tests interact with the kvstore and depend on a local kvstore instances of
etcd. To start the local instances, run:

.. code-block:: shell-session

     $ make start-kvstores

Running all tests
^^^^^^^^^^^^^^^^^

To run integration tests over the entire repository, run the following command
in the project root directory:

.. code-block:: shell-session

    $ make integration-tests

To run just unit tests, run:

.. code-block:: shell-session

    $ go test ./...

Testing individual packages
^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is possible to test individual packages by invoking ``go test`` directly.
You can then ``cd`` into the package subject to testing and invoke go test:

.. code-block:: shell-session

    $ cd pkg/kvstore
    $ go test


If you need more verbose output, you can pass in the ``-check.v`` and
``-check.vv`` arguments:

.. code-block:: shell-session

    $ cd pkg/kvstore
    $ go test -check.v -check.vv

Integration tests have some prerequisites like
:ref:`integration_testing_prerequisites`, you can use the following command to
automatically set up the prerequisites, run the unit tests and tear down the
prerequisites:

.. code-block:: shell-session

    $ make integration-tests TESTPKGS=./pkg/kvstore

Some tests are marked as 'privileged' if they require the test suite to be run
as a privileged user or with a given set of capabilities. They are skipped by
default when running ``go test``.

There are a few ways to run privileged tests.

1. Run the whole test suite with sudo.

    .. code-block:: shell-session

        $ sudo make tests-privileged

2. To narrow down the packages under test, specify ``TESTPKGS``. Note that this
   takes the Go package pattern syntax, including ``...`` wildcard specifier.

    .. code-block:: shell-session

        $ sudo make tests-privileged TESTPKGS="./pkg/datapath/linux ./pkg/maps/..." 

3. Set the ``PRIVILEGED_TESTS`` environment variable and run ``go test``
   directly. This only escalates privileges when executing the test binaries,
   the ``go build`` process is run unprivileged.

    .. code-block:: shell-session

        $ PRIVILEGED_TESTS=true go test -exec "sudo -E" ./pkg/ipam

Running individual tests
^^^^^^^^^^^^^^^^^^^^^^^^

Due to the use of gocheck, the standard ``go test -run`` will not work,
instead, the ``-check.f`` argument has to be specified:

.. code-block:: shell-session

    $ go test -check.f TestParallelAllocation

Automatically run unit tests on code changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The script ``contrib/shell/test.sh`` contains some helpful bash functions to
improve the feedback cycle between writing tests and seeing their results. If
you're writing unit tests in a particular package, the ``watchtest`` function
will watch for changes in a directory and run the unit tests for that package
any time the files change. For example, if writing unit tests in ``pkg/policy``,
run this in a terminal next to your editor:

.. code-block:: shell-session

    $ . contrib/shell/test.sh
    $ watchtest pkg/policy

This shell script depends on the ``inotify-tools`` package on Linux.

.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _unit_testing:

Unit Testing
============

Cilium uses the standard `go test <https://golang.org/pkg/testing/>`__ framework
in combination with `gocheck <http://labix.org/gocheck>`__ for richer testing
functionality.

.. _unit_testing_prerequisites:

Prerequisites
^^^^^^^^^^^^^

Some tests interact with the kvstore and depend on a local kvstore instances of
both etcd and consul. To start the local instances, run:

.. code-block:: shell-session

     $ make start-kvstores

Running all tests
^^^^^^^^^^^^^^^^^

To run unit tests over the entire repository, run the following command in the
project root directory:

.. code-block:: shell-session

    $ make unit-tests

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

If the unit tests have some prerequisites like :ref:`unit_testing_prerequisites`,
you can use the following command to automatically set up the prerequisites,
run the unit tests and tear down the prerequisites:

.. code-block:: shell-session

    $ make unit-tests TESTPKGS=pkg/kvstore

Some packages have privileged tests. They are not run by default when you run
the unit tests for the respective package. The privileged test files have an
entry at the top of the test file as shown.

::

    +build privileged_tests

There are two ways that you can run the 'privileged' tests.

1. To run all the 'privileged' tests for cilium follow the instructions below.

    .. code-block:: shell-session

        $ sudo -E make tests-privileged

2. To run a specific package 'privileged' test, follow the instructions below.
   Here for example we are trying to run the tests for 'routing' package.

    .. code-block:: shell-session

        $ TESTPKGS="pkg/aws/eni/routing" sudo -E make tests-privileged

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

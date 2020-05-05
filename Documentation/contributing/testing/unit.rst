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

::

     $ make start-kvstores

Running all tests
^^^^^^^^^^^^^^^^^

To run unit tests over the entire repository, run the following command in the
project root directory:

::

    $ make unit-tests

Testing individual packages
^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is possible to test individual packages by invoking ``go test`` directly.
You can then ``cd`` into the package subject to testing and invoke go test:

::

    $ cd pkg/kvstore
    $ go test


If you need more verbose output, you can pass in the ``-check.v`` and
``-check.vv`` arguments:

::

    $ cd pkg/kvstore
    $ go test -check.v -check.vv

If the unit tests have some prerequisites like :ref:`unit_testing_prerequisites`,
you can use the following command to automatically set up the prerequisites,
run the unit tests and tear down the prerequisites:

::

    $ make unit-tests TESTPKGS=github.com/cilium/cilium/pkg/kvstore

Running individual tests
^^^^^^^^^^^^^^^^^^^^^^^^

Due to the use of gocheck, the standard ``go test -run`` will not work,
instead, the ``-check.f`` argument has to be specified:

::

    $ go test -check.f TestParallelAllocation

Automatically run unit tests on code changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The script ``contrib/shell/test.sh`` contains some helpful bash functions to
improve the feedback cycle between writing tests and seeing their results. If
you're writing unit tests in a particular package, the ``watchtest`` function
will watch for changes in a directory and run the unit tests for that package
any time the files change. For example, if writing unit tests in ``pkg/policy``,
run this in a terminal next to your editor:

.. code:: bash

    $ . contrib/shell/test.sh
    $ watchtest pkg/policy

This shell script depends on the ``inotify-tools`` package on Linux.

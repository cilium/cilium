.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _integration_testing:

Integration Testing
===================

Cilium uses the standard `go test <https://golang.org/pkg/testing/>`__ framework.
All new tests must use `the standard test framework`_.

Historically, `gocheck <https://gopkg.in/check.v1>`__ has also been used. 
Many tests are still written using ``gocheck``, which creates some
unfortunate consequences:

1. Adding a test helper requires writing two versions: one for ``testing.T``
   and one for ``check.C``.

2. Executing ``gocheck`` tests requires non-standard flags.

For this reason ``gopkg.in/check.v1`` has switched to a fork called
``github.com/cilium/checkmate``, which removes most of the problematic bits.
You can migrate away from ``gocheck`` by following the procedure outlined
in :ref:`migrate-gocheck`.

.. _the standard test framework: https://github.com/cilium/cilium/issues/16860

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

.. _migrate-gocheck:

Migrating tests off of ``gopkg.in/check.v1``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Cilium codebase has historically used ``gopkg.in/check.v1`` to write unit and
integration tests. Most of the functionality offered by that package is now
present in `testing`_. What ``gocheck`` calls checkers are now available in
``testify``, in either `assert`_ or `require`_ form.

* ``check.Equals``: ``require.EqualValues``

* ``check.HasLen``: ``require.Len``

* ``check.ErrorMatches``: ``require.ErrorContains`` (doesn't support regex)

* ``checker.Equals`` and ``checker.DeepEquals``: ``require.Equal``

It's best to replace ``check.C.Assert`` with ``require`` calls instead of ``assert`` because the latter doesn't stop test execution if the assertion fails.

``gopkg.in/check.v1`` has been replaced with ``github.com/cilium/checkmate``, which
means that ``check.C`` now implements `testing.TB <https://pkg.go.dev/testing#TB>`__
and can be passed to test helpers that take ``testing.TB``.

The end goal is to remove all uses of ``checkmate`` from the codebase.
To convert a ``gocheck`` test, use the following approach:

1. Replace ``SetUp`` fixtures with helpers that take ``testing.TB``.

2. Replace ``TearDown`` fixtures with calls to ``testing.TB.Cleanup()``,
   possibly in the helper you added to replace ``SetUp``.

3. Replace calls to ``c.Assert`` with ``require`` equivalents.

4. Replace tests methods with a normal ``func TestHelloWorld(t *testing.T)``
   function.

Let's take an example from the ``gocheck`` documentation and migrate it:

.. code-block:: go

    package hello_test

    import (
        "testing"

        . "gopkg.in/check.v1"
    )

    func Test(t *testing.T) { TestingT(t) }

    type MySuite struct{}

    var _ = Suite(&MySuite{})

    func (s *MySuite) SetUpTest(c *C) {
        // setup code
    }

    func (s *MySuite) TearDownTest(c *C) {
        // cleanup code
    }

    func (s *MySuite) TestHelloWorld(c *C) {
        c.Assert(42, Equals, "42")
    }

    type SomeOtherSuite struct{}

    var _ = Suite(&SomeOtherSuite{})

    func (s *SomeOtherSuite) TestTheRealAnswer(c *C) {
        c.Assert("42", Equals, "42")
    }

After applying the previous rules you should end up with something like this:

.. code-block:: go

    package hello_test

    import (
        "testing"

        . "github.com/cilium/checkmate"
        "github.com/stretchr/testify/assert"
    )

    func Test(t *testing.T) { TestingT(t) }

    func setupHelper(tb testing.TB) {
        tb.Helper()

        // setup code

        tb.Cleanup(func() {
            // cleanup code
        })
    }

    func TestHelloWorld(t *testing.T) {
        setupHelper(t)

        require.Equal(t, 42, "42")
    }

    type SomeOtherSuite struct{}

    var _ = Suite(&SomeOtherSuite{})

    func (s *SomeOtherSuite) TestTheRealAnswer(c *C) {
        require.Equal(c, "42", "42")
    }

As you can see we didn't get round to converting all tests yet.
Since ``C`` now implements ``testing.TB`` we can call ``require.Equal`` from
``TestTheRealAnswer()`` without problems.

.. _assert: https://pkg.go.dev/github.com/stretchr/testify/assert
.. _require: https://pkg.go.dev/github.com/stretchr/testify/require
.. _testing: https://golang.org/pkg/testing/

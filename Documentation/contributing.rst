.. _dev_guide:

Developer / Contributor Guide
=============================

We're happy you're interested in contributing to the Cilium project.

This guide will help you make sure you have an environment capable of testing
changes to the Cilium source code, and that you understand the workflow of getting
these changes reviewed and merged upstream.

If you're interested in contributing, but don't know where to start, then you
should consider looking through the `good-first-issue <https://github.com/cilium/cilium/issues?q=is%3Aopen+is%3Aissue+label%3Agood-first-issue>`_
tag on the Cilium github issues page. Other small tasks are often tagged with
the `kind/microtask <https://github.com/cilium/cilium/issues?q=is%3Aopen+is%3Aissue+label%3Akind%2Fmicrotask>`_
label.

Setting up a development environment
------------------------------------

Developer requirements
~~~~~~~~~~~~~~~~~~~~~~

You need to have the following tools available in order to effectively
contribute to Cilium:

+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
| Dependency                                                                       | Version / Commit ID      | Download Command                                                              |
+==================================================================================+==========================+===============================================================================+
| git                                                                              | latest                   | N/A (OS-specific)                                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
| `go <https://golang.org/dl/>`_                                                   | 1.9                      | N/A (OS-specific)                                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
| `dep <https://github.com/golang/dep/>`_                                          | >= v0.4.1                | ``curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh``  |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
| `go-bindata <https://github.com/cilium/go-bindata>`_                             | ``a0ff2567cfb``          | ``go get -u github.com/cilium/go-bindata/...``                                |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `ginkgo <https://github.com/onsi/ginkgo>`__                                      | >= 1.4.0                 | ``go get -u github.com/onsi/ginkgo``                                          |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `gomega <https://github.com/onsi/gomega>`_                                       | >= 1.2.0                 | ``go get -u github.com/onsi/gomega``                                          |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `Kubernetes code generator <https://github.com/kubernetes/code-generator>`_      | kubernetes-1.10.0        | ``go get -u k8s.io/code-generator``                                           |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
| `protoc-gen-go <https://github.com/golang/protobuf/tree/master/protoc-gen-go>`_  | latest                   | ``go get -u github.com/golang/protobuf/protoc-gen-go``                        |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
| `protoc-gen-validate <https://github.com/lyft/protoc-gen-validate>`_             | latest                   | ``go get -u github.com/lyft/protoc-gen-validate``                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `Docker <https://docs.docker.com/engine/installation/>`_                         | OS-Dependent             | N/A (OS-specific)                                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `Docker-Compose <https://docs.docker.com/compose/install/>`_                     | OS-Dependent             | N/A (OS-specific)                                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `Cmake  <https://cmake.org/download/>`_                                          | OS-Dependent             | N/A (OS-specific)                                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `Bazel <https://docs.bazel.build/versions/master/install.html>`_                 | 0.13.0                   | N/A (OS-specific)                                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `Libtool <https://www.gnu.org/software/libtool/>`_                               | >= 1.4.2                 | N/A (OS-specific)                                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `Automake <https://www.gnu.org/software/automake/>`_                             | OS-Dependent             | N/A (OS-specific)                                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `Kubecfg <https://github.com/ksonnet/kubecfg>`_                                  | >=0.8.0                  | go get github.com/ksonnet/kubecfg                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+


To run Cilium locally on VMs, you need:

+----------------------------------------------------------------------------------+-----------------------+--------------------------------------------------------------------------------+
| Dependency                                                                       | Version / Commit ID   | Download Command                                                               |
+==================================================================================+=======================+================================================================================+
| `Vagrant <https://www.vagrantup.com/downloads.html>`_                            | >= 2.0                | `Vagrant Install Instructions <https://www.vagrantup.com/docs/installation/>`_ |
+----------------------------------------------------------------------------------+-----------------------+--------------------------------------------------------------------------------+
| `VirtualBox <https://www.virtualbox.org/wiki/Downloads>`_ (if not using libvirt) | >= 5.2                | N/A (OS-specific)                                                              |
+----------------------------------------------------------------------------------+-----------------------+--------------------------------------------------------------------------------+

Finally, in order to build the documentation, you should have Sphinx installed:

::

    $ sudo pip install sphinx

You should start with the `gs_guide`, which walks you through the set-up, such
as installing Vagrant, getting the Cilium sources, and going through some
Cilium basics.


Vagrant Setup
~~~~~~~~~~~~~

While the `gs_guide` uses a Vagrantfile tuned for the basic walk through, the
setup for the Vagrantfile in the root of the Cilium tree depends on a number of
environment variables and network setup that are managed via
``contrib/vagrant/start.sh``.

Using the provided Vagrantfile
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To bring up a Vagrant VM  with Cilium
plus dependencies installed, run:

::

    $ contrib/vagrant/start.sh

This will create and run a vagrant VM based on the base box
``cilium/ubuntu``. The box is currently available for the
following providers:

* virtualbox

Options
^^^^^^^

The following environment variables can be set to customize the VMs
brought up by vagrant:

* ``NWORKERS=n``: Number of child nodes you want to start with the master,
  default 0.
* ``RELOAD=1``: Issue a ``vagrant reload`` instead of ``vagrant up``, useful
  to resume halted VMs.
* ``NFS=1``: Use NFS for vagrant shared directories instead of rsync.
* ``K8S=1``: Build & install kubernetes on the nodes. ``k8s1`` is the master
  node, which contains both master components: etcd, kube-controller-manager,
  kube-scheduler, kube-apiserver, and node components: kubelet,
  kube-proxy, kubectl and Cilium. When used in combination with ``NWORKERS=1`` a
  second node is created, where ``k8s2`` will be a kubernetes node, which
  contains: kubelet, kube-proxy, kubectl and cilium.
* ``IPV4=1``: Run Cilium with IPv4 enabled.
* ``RUNTIME=x``: Sets up the container runtime to be used inside a kubernetes
  cluster. Valid options are: ``docker``, ``containerd`` and ``crio``. If not
  set, it defaults to ``docker``.
* ``VAGRANT_DEFAULT_PROVIDER={virtualbox \| libvirt \| ...}``

If you want to start the VM with cilium enabled with ``containerd``, with
kubernetes installed and plus a worker, run:

::

	$ RUNTIME=containerd K8S=1 NWORKERS=1 contrib/vagrant/start.sh

If you have any issue with the provided vagrant box
``cilium/ubuntu`` or need a different box format, you may
build the box yourself using the `packer scripts <https://github.com/cilium/packer-ci-build>`_

Manual Installation
^^^^^^^^^^^^^^^^^^^

Alternatively you can import the vagrant box ``cilium/ubuntu``
directly and manually install Cilium:

::

        $ vagrant init cilium/ubuntu
        $ vagrant up
        $ vagrant ssh [...]
        $ cd go/src/github.com/cilium/cilium/
        $ make
        $ sudo make install
        $ sudo mkdir -p /etc/sysconfig/
        $ sudo cp contrib/systemd/cilium.service /etc/systemd/system/
        $ sudo cp contrib/systemd/cilium  /etc/sysconfig/cilium
        $ sudo usermod -a -G cilium vagrant
        $ sudo systemctl enable cilium
        $ sudo systemctl restart cilium

Notes
^^^^^

Your Cilium tree is mapped to the VM so that you do not need to keep manually
copying files between your host and the VM. Folders are by default synced
automatically using `VirtualBox Shared Folders <https://www.virtualbox.org/manual/ch04.html#sharedfolders>`_ .
You can also use NFS to access your Cilium tree from the VM by
setting the environment variable ``NFS`` (mentioned above) before running the
startup script (``export NFS=1``). Note that your host firewall must have a variety
of port open. The Vagrantfile will inform you of the configuration of these addresses
and ports to enable NFS.

.. note::

   OSX file system is by default case insensitive, which can confuse
   git.  At the writing of this Cilium repo has no file names that
   would be considered referring to the same file on a case
   insensitive file system.  Regardless, it may be useful to create a
   disk image with a case sensitive file system for holding your git
   repos.

.. note::

   VirtualBox for OSX currently (version 5.1.22) always reports
   host-only networks' prefix length as 64.  Cilium needs this prefix
   to be 16, and the startup script will check for this.  This check
   always fails when using VirtualBox on OSX, but it is safe to let
   the startup script to reset the prefix length to 16.

If for some reason, running of the provisioning script fails, you should bring the VM down before trying again:

::

    $ vagrant halt

Packer-CI-Build
^^^^^^^^^^^^^^^

As part of Cilium development, we use a custom base box with a bunch of
pre-installed libraries and tools that we need to enhance our daily workflow.
That base box is built with `Packer <https://www.packer.io/>`_ and it is hosted
in the `packer-ci-build
<https://jenkins.cilium.io/job/Vagrant-Master-Boxes-Packer-Build/>`_ GitHub
repository.

New versions of this box can be created via `Jenkins
<https://jenkins.cilium.io/job/Vagrant-Master-Boxes-Packer-Build/>`_, where
new builds of the image will be pushed to  `Vagrant Cloud
<https://app.vagrantup.com/cilium>`_ . The version of the image corresponds to
the `BUILD_ID <https://qa.nuxeo.org/jenkins/pipeline-syntax/globals#env>`_
environment variable in the Jenkins job. That version ID will be used in Cilium
`Vagrantfiles
<https://github.com/cilium/cilium/blob/master/test/Vagrantfile#L10>`_.

Changes to this image are made via contributions to the packer-ci-build
repository. Authorized GitHub users can trigger builds with a GitHub comment on
the PR containing the trigger phrase ``build-me-please``. In case that a new box
needs to be rebased with a different branch than master, authorized developers
can run the build with custom parameters. To use a different Cilium branch in
the `job <https://jenkins.cilium.io/job/Vagrant-Master-Boxes-Packer-Build/>`_ go
to *Build with parameters* and a base branch can be set as the user needs.

This box will need to be updated when a new developer needs a new dependency
that is not installed in the current version of the box, or if a dependency that
is cached within the box becomes stale.

Unit Testing
------------

Cilium uses the standard `go test <https://golang.org/pkg/testing/>`__ framework
in combination with `gocheck <http://labix.org/gocheck>`__ for richer testing
functionality.

Running all tests
~~~~~~~~~~~~~~~~~

To run unit tests over the entire repository, run the following command in the
project root directory:

::

    $ make unit-tests

.. Warning::

 Running envoy unit tests  can sometimes cause the developer VM to run out of
 memory. This pressure can be alleviated by shutting down the bazel caching
 daemon left by these tests. Run ``(cd envoy; bazel shutdown)`` after a build to
 do this.

Testing individual packages
~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is possible to test individual packages by invoking ``go test`` directly.
Before doing so, ensure that the kvstore dependency is met for testing. You can
start a local etcd and consul instance by running:

::

     $ make start-kvstores


You can then ``cd`` into the package subject to testing and invoke go test:

::

    $ cd pkg/kvstore
    $ go test


If you need more verbose output, you can pass in the ``-check.v`` and
``-check.vv`` arguments:

::

    $ cd pkg/kvstore
    $ go test -check.v -check.vv

Running individual tests
~~~~~~~~~~~~~~~~~~~~~~~~

Due to the use of gocheck, the standard ``go test -run`` will not work,
instead, the ``-check.f`` argument has to be specified:

::

    $ go test -check.f TestParallelAllocation

Automatically run unit tests on code changes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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


Testing Cilium Locally Using Developer VM
-----------------------------------------

The Vagrantfile in the Cilium repo root (hereon just ``Vagrantfile``), exists
specifically for the ease of provisioning and testing Cilium locally for
developers. When the VM is started, it builds and installs Cilium.
After the initial build and install you can do further building and
testing incrementally inside the VM. ``vagrant ssh`` takes you to the
Cilium source tree directory
(``/home/vagrant/go/src/github.com/cilium/cilium``) by default, and the
following commands assume that you are working within that directory.

Build Cilium
~~~~~~~~~~~~

Assuming you have synced (rsync) the source tree after you have made
changes, or the tree is automatically in sync via NFS or guest
additions folder sharing, you can issue a build as follows:

::

    $ make

A successful build should be followed by running the unit tests:

::

    $ make unit-tests

Install Cilium
~~~~~~~~~~~~~~

After a successful build and test you can re-install Cilium by:

::

    $ sudo -E make install

Restart Cilium service
~~~~~~~~~~~~~~~~~~~~~~

To run the newly installed version of Cilium, restart the service:

::

    $ sudo systemctl restart cilium

You can verify the service and cilium-agent status by the following
commands, respectively:

::

    $ sudo systemctl status cilium
    $ cilium status

.. _testsuite:

End-To-End Testing Framework
----------------------------

Introduction
~~~~~~~~~~~~

Cilium uses `Ginkgo <https://onsi.github.io/ginkgo>`_ as a testing framework for
writing end-to-end tests which test Cilium all the way from the API level (e.g.
importing policies, CLI) to the datapath (i.e, whether policy that is imported
is enforced accordingly in the datapath).  The tests in the ``test`` directory
are built on top of Ginkgo. Ginkgo provides a rich framework for developing
tests alongside the benefits of Golang (compilation-time checks, types, etc.).
To get accustomed to the basics of Ginkgo, we recommend reading the `Ginkgo
Getting-Started Guide
<https://onsi.github.io/ginkgo/#getting-started-writing-your-first-test>`_ , as
well as running `example tests
<https://github.com/onsi/composition-ginkgo-example>`_ to get a feel for the
Ginkgo workflow.

These test scripts will invoke ``vagrant`` to create virtual machine(s) to
run the tests. The tests make heavy use of the Ginkgo `focus <https://onsi.github.io/ginkgo/#focused-specs>`_ concept to
determine which VMs are necessary to run particular tests. All test names
*must* begin with one of the following prefixes:

* ``Runtime``: Test cilium in a runtime environment running on a single node.
* ``K8s``: Create a small multi-node kubernetes environment for testing
  features beyond a single host, and for testing kubernetes-specific features.
* ``Nightly``: sets up a multinode Kubernetes cluster to run scale, performance, and chaos testing for Cilium.

Running End-To-End Tests
~~~~~~~~~~~~~~~~~~~~~~~~

Running All Tests
^^^^^^^^^^^^^^^^^

Running all of the Ginkgo tests may take an hour or longer. To run all the
ginkgo tests, invoke the make command as follows from the root of the cilium
repository:

::

    $ sudo make -C test/

The first time that this is invoked, the testsuite will pull the
`testing VMs <https://app.vagrantup.com/cilium/boxes/ginkgo>`_ and provision
Cilium into them. This may take several minutes, depending on your internet
connection speed. Subsequent runs of the test will reuse the image.

Running Runtime Tests
^^^^^^^^^^^^^^^^^^^^^

To run all of the runtime tests, execute the following command from the ``test`` directory:

::

    ginkgo --focus="Runtime*" -noColor

Ginkgo searches for all tests in all subdirectories that are "named" beginning
with the string "Runtime" and contain any characters after it. For instance,
here is an example showing what tests will be ran using Ginkgo's dryRun option:

::

    $ ginkgo --focus="Runtime*" -noColor -v -dryRun
    Running Suite: runtime
    ======================
    Random Seed: 1516125117
    Will run 42 of 164 specs
    ................
    RuntimePolicyEnforcement Policy Enforcement Always
      Always to Never with policy
      /Users/ianvernon/go/src/github.com/cilium/cilium/test/runtime/Policies.go:258
    •
    ------------------------------
    RuntimePolicyEnforcement Policy Enforcement Always
      Always to Never without policy
      /Users/ianvernon/go/src/github.com/cilium/cilium/test/runtime/Policies.go:293
    •
    ------------------------------
    RuntimePolicyEnforcement Policy Enforcement Never
      Container creation
      /Users/ianvernon/go/src/github.com/cilium/cilium/test/runtime/Policies.go:332
    •
    ------------------------------
    RuntimePolicyEnforcement Policy Enforcement Never
      Never to default with policy
      /Users/ianvernon/go/src/github.com/cilium/cilium/test/runtime/Policies.go:349
    .................
    Ran 42 of 164 Specs in 0.002 seconds
    SUCCESS! -- 0 Passed | 0 Failed | 0 Pending | 122 Skipped PASS

    Ginkgo ran 1 suite in 1.830262168s
    Test Suite Passed

The output has been truncated. For more information about this functionality,
consult the aforementioned Ginkgo documentation.

Running Kubernetes Tests
^^^^^^^^^^^^^^^^^^^^^^^^

To run all of the Kubernetes tests, run the following command from the ``test`` directory:

::

    ginkgo --focus="K8s*" -noColor


Similar to the Runtime test suite, Ginkgo searches for all tests in all
subdirectories that are "named" beginning with the string "K8s" and
contain any characters after it.

The Kubernetes tests support the following Kubernetes versions:

* 1.7
* 1.8
* 1.9
* 1.10
* 1.11

By default, the Vagrant VMs are provisioned with Kubernetes 1.9. To run with any other
supported version of Kubernetes, run the test suite with the following format:

::

    K8S_VERSION=<version> ginkgo --focus="K8s*" -noColor

Running Nightly Tests
^^^^^^^^^^^^^^^^^^^^^

To run all of the Nightly tests, run the following command from the ``test`` directory:

::

    ginkgo --focus="Nightly*"  -noColor

Similar to the other test suites, Ginkgo searches for all tests in all
subdirectories that are "named" beginning with the string "Nightly" and contain
any characters after it. The default version of running Nightly test are 1.8,
but can be changed using the environment variable ``K8S_VERSION``.

Nightly Testing Jenkins Setup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Nightly tests run once per day in the `Cilium-Nightly-Tests Job <https://jenkins.cilium.io/job/Cilium-Master-Nightly-Tests-All/>`_.
The configuration for this job is stored in ``Jenkinsfile.nightly``.

To see the results of these tests, you can view the JUnit Report for an individual job:

1. Click on the build number you wish to get test results from on the left hand
   side of the `Cilium-Nightly-Tests Job
   <https://jenkins.cilium.io/job/Cilium-Master-Nightly-Tests-All/>`_.
2. Click on 'Test Results' on the left side of the page to view the results from the build.
   This will give you a report of which tests passed and failed. You can click on each test
   to view its corresponding output created from Ginkgo.

Available CLI Options
^^^^^^^^^^^^^^^^^^^^^

For more advanced workflows, check the list of available custom options for the Cilium
framework in the ``test/`` directory and interact with ginkgo directly:

::

    $ cd test/
    $ ginkgo . -- --help | grep -A 1 cilium
      -cilium.SSHConfig string
            Specify a custom command to fetch SSH configuration (eg: 'vagrant ssh-config')
      -cilium.holdEnvironment
            On failure, hold the environment in its current state
      -cilium.provision
            Provision Vagrant boxes and Cilium before running test (default true)
      -cilium.showCommands
            Output which commands are ran to stdout
      -cilium.dsManifest
            Cilium daemon set manifest to use for running the test (only Kubernetes)
    $ ginkgo --focus "Policies*" -- --cilium.provision=false

For more information about other built-in options to Ginkgo, consult the
`Ginkgo documentation <https://onsi.github.io/ginkgo/>`_.

Running Specific Tests Within a Test Suite
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you want to run one specified test, there are a few options:

* By modifying code: add the prefix "FIt" on the test you want to run; this marks the test as focused. Ginkgo will skip other tests and will only run the "focused" test. For more information, consult the `Focused Specs <https://onsi.github.io/ginkgo/#focused-specs>`_ documentation from Ginkgo.

::

    It("Example test", func(){
        Expect(true).Should(BeTrue())
    })

    FIt("Example focused test", func(){
        Expect(true).Should(BeTrue())
    })


* From the command line: specify a more granular focus if you want to focus on, say, L7 tests:

::

    ginkgo --focus "Run*" --focus "L7 "


This will focus on tests prefixed with "Run*", and within that focus, run any
test that starts with "L7".

Test Reports
~~~~~~~~~~~~

The Cilium Ginkgo framework formulates JUnit reports for each test. The
following files currently are generated depending upon the test suite that is ran:

* runtime.xml
* K8s.xml

Best Practices for Writing Tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Provide informative output to console during a test using the `By construct <https://onsi.github.io/ginkgo/#documenting-complex-its-by>`_. This helps with debugging and gives those who did not write the test a good idea of what is going on. The lower the barrier of entry is for understanding tests, the better our tests will be!
* Leave the testing environment in the same state that it was in when the test started by deleting resources, resetting configuration, etc.
* Gather logs in the case that a test fails. If a test fails while running on Jenkins, a postmortem needs to be done to analyze why. So, dumping logs to a location where Jenkins can pick them up is of the highest imperative. Use the following code in an ``AfterFailed`` method:

::

	AfterFailed(func() {
		vm.ReportFailed()
	})


Ginkgo Extensions
~~~~~~~~~~~~~~~~~

In Cilium, some Ginkgo features are extended to cover some uses cases that are
useful for testing Cilium.

BeforeAll
^^^^^^^^^

This function will run before all `BeforeEach
<https://onsi.github.io/ginkgo/#extracting-common-setup-beforeeach>`_ within a
`Describe or Context
<https://onsi.github.io/ginkgo/#organizing-specs-with-containers-describe-and-context>`_.
This method is an equivalent to ``SetUp`` or initialize functions in common
unit test frameworks.

AfterAll
^^^^^^^^

This method will run after all `AfterEach
<https://onsi.github.io/ginkgo/#extracting-common-setup-beforeeach>`_ functions
defined in a `Describe or Context
<https://onsi.github.io/ginkgo/#organizing-specs-with-containers-describe-and-context>`_.
This method is used for tearing down objects created which are used by all
``Its`` within the given ``Context`` or ``Describe``. It is ran after all Its
have ran, this method is a equivalent to ``tearDown`` or ``finalize`` methods in
common unit test frameworks.

A good use case for using ``AfterAll`` method is to remove containers or pods
that are needed for multiple ``Its`` in the given ``Context`` or ``Describe``.

JustAfterEach
^^^^^^^^^^^^^

This method will run just after each test and before ``AfterFailed`` and
``AfterEach``. The main reason of this method is to to perform some assertions
for a group of tests.  A good example of using a global ``JustAfterEach``
function is for deadlock detection, which checks the Cilium logs for deadlocks
that may have occurred in the duration of the tests.

AfterFailed
^^^^^^^^^^^

This method will run before all ``AfterEach`` and after ``JustAfterEach``. This
function is only called when the test failed.This construct is used to gather
logs, the status of Cilium, etc, which provide data for analysis when tests
fail.

Example Test Layout
^^^^^^^^^^^^^^^^^^^

Here is an example layout of how a test may be written with the aforementioned
constructs:

Test description diagram:
::

    Describe
        BeforeAll(A)
        AfterAll(A)
        AfterFailed(A)
        AfterEach(A)
        JustAfterEach(A)
        TESTA1
        TESTA2
        TESTA3
        Context
            BeforeAll(B)
            AfterAll(B)
            AfterFailed(B)
            AfterEach(B)
            JustAfterEach(B)
            TESTB1
            TESTB2
            TESTB3


Test execution flow:
::

    Describe
        BeforeAll
        TESTA1; JustAfterEach(A), AfterFailed(A), AfterEach(A)
        TESTA2; JustAfterEach(A), AfterFailed(A), AfterEach(A)
        TESTA3; JustAfterEach(A), AfterFailed(A), AfterEach(A)
        Context
            BeforeAll(B)
            TESTB1:
               JustAfterEach(B); JustAfterEach(A)
               AfterFailed(B); AfterFailed(A);
               AfterEach(B) ; AfterEach(A);
            TESTB2:
               JustAfterEach(B); JustAfterEach(A)
               AfterFailed(B); AfterFailed(A);
               AfterEach(B) ; AfterEach(A);
            TESTB3:
               JustAfterEach(B); JustAfterEach(A)
               AfterFailed(B); AfterFailed(A);
               AfterEach(B) ; AfterEach(A);
            AfterAll(B)
        AfterAll(A)

Debugging:
~~~~~~~~~~

Ginkgo provides to us different ways of debugging. In case that you want to see
all the logs messages in the console you can run the test in verbose mode using
the option ``-v``:

::

	ginkgo --focus "Runtime*" -v

In case that the verbose mode is not enough, you can retrieve all run commands
and their output in the report directory (``./test/test-results``). Each test
creates a new folder, which contains a file called log where all information is
saved, in case of a failing test an exhaustive data will be added.

::

	$ head test/test_results/RuntimeKafkaKafkaPolicyIngress/logs
	level=info msg=Starting testName=RuntimeKafka
	level=info msg="Vagrant: running command \"vagrant ssh-config runtime\""
	cmd: "sudo cilium status" exitCode: 0
	 KVStore:            Ok         Consul: 172.17.0.3:8300
	ContainerRuntime:   Ok
	Kubernetes:         Disabled
	Kubernetes APIs:    [""]
	Cilium:             Ok   OK
	NodeMonitor:        Disabled
	Allocated IPv4 addresses:


Running with delve
^^^^^^^^^^^^^^^^^^

`Delve <https://github.com/derekparker/delve>`_ is a debugging tool for Go
applications. If you want to run your test with delve,  you should add a new
breakpoint using
`runtime.BreakPoint() <https://golang.org/pkg/runtime/#Breakpoint>`_ in the
code, and run ginkgo using ``dlv``.

Example how to run ginkgo using ``dlv``:

::

	dlv test . -- --ginkgo.focus="Runtime" -ginkgo.v=true --cilium.provision=false


Running End-To-End Tests In Other Environments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to run tests in a different VM, you can use ``--cilium.SSHConfig`` to
provide the SSH configuration of the endpoint on which tests will be ran. The
tests presume the following on the remote instance:

- Cilium source code is located in the directory ``/home/vagrant/go/src/github.com/cilium/cilium/``.
- Cilium is installed and running.

The ssh connection needs to be defined as a ``ssh-config`` file and need to have
the following targets:

- runtime: To run runtime tests
- k8s{1..2}-${K8S_VERSION}: to run Kubernetes tests. These instances must have
  Kubernetes installed and running as a prerequisite for running tests.

An example ``ssh-config`` can be the following:

::

	Host runtime
	  HostName 127.0.0.1
	  User vagrant
	  Port 2222
	  UserKnownHostsFile /dev/null
	  StrictHostKeyChecking no
	  PasswordAuthentication no
	  IdentityFile /home/eloy/.go/src/github.com/cilium/cilium/test/.vagrant/machines/runtime/virtualbox/private_key
	  IdentitiesOnly yes
	  LogLevel FATAL

To run this you can use the following command:

::

    ginkgo  -v -- --cilium.provision=false --cilium.SSHConfig="cat ssh-config"


VMs for Testing
~~~~~~~~~~~~~~~~

The VMs used for testing are defined in ``test/Vagrantfile``. There are a variety of
configuration options that can be passed as environment variables:

+----------------------+-----------------+--------------+------------------------------------------------------------------+
| ENV variable         | Default Value   | Options      | Description                                                      |
+======================+=================+==============+==================================================================+
| K8S\_NODES           | 2               | 0..100       | Number of Kubernetes nodes in the cluster                        |
+----------------------+-----------------+--------------+------------------------------------------------------------------+
| NFS                  | 0               | 1            | If Cilium folder needs to be shared using NFS                    |
+----------------------+-----------------+--------------+------------------------------------------------------------------+
| IPv6                 | 0               | 0-1          | If 1 the Kubernetes cluster will use IPv6                        |
+----------------------+-----------------+--------------+------------------------------------------------------------------+
| CONTAINER\_RUNTIME   | docker          | containerd   | To set the default container runtime in the Kubernetes cluster   |
+----------------------+-----------------+--------------+------------------------------------------------------------------+
| K8S\_VERSION         | 1.10            | 1.\*\*       | Kubernetes version to install                                    |
+----------------------+-----------------+--------------+------------------------------------------------------------------+

Further Assistance
~~~~~~~~~~~~~~~~~~

Have a question about how the tests work or want to chat more about improving the
testing infrastructure for Cilium? Hop on over to the
`testing <https://cilium.slack.com/messages/C7PE7V806>`_ channel on Slack.

Building Documentation
----------------------

The documentation has several dependencies which can be installed using pip:

::

    $ pip install -r Documentation/requirements.txt

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

Now the documentation page should be browsable on http://localhost:8080.

Debugging datapath code
~~~~~~~~~~~~~~~~~~~~~~~

.. note::

    See also the user troubleshooting guide in the section :ref:`admin_guide`.

One of the most common issues when developing datapath code is that the BPF
code cannot be loaded into the kernel. This frequently manifests as the
endpoints appearing in the "not-ready" state and never switching out of it:

.. code:: bash

    $ cilium endpoint list
    ENDPOINT   POLICY        IDENTITY   LABELS (source:key[=value])   IPv6                     IPv4            STATUS
               ENFORCEMENT
    48896      Disabled      266        container:id.server           fd02::c0a8:210b:0:bf00   10.11.13.37     not-ready
    60670      Disabled      267        container:id.client           fd02::c0a8:210b:0:ecfe   10.11.167.158   not-ready

Running ``cilium endpoint get`` for one of the endpoints will provide a
description of known state about it, which includes BPF verification logs.

The files under ``/var/run/cilium/state`` provide context about how the BPF
datapath is managed and set up. The .log files will describe the BPF
requirements and features that Cilium detected and used to generate the BPF
programs. The .h files describe specific configurations used for BPF program
compilation. The numbered directories describe endpoint-specific state,
including header configuration files and BPF binaries.

.. code:: bash

    # for log in /var/run/cilium/state/*.log; do echo "cat $log"; cat $log; done
    cat /var/run/cilium/state/bpf_features.log
    BPF/probes: CONFIG_CGROUP_BPF=y is not in kernel configuration
    BPF/probes: CONFIG_LWTUNNEL_BPF=y is not in kernel configuration
    HAVE_LPM_MAP_TYPE: Your kernel doesn't support LPM trie maps for BPF, thus disabling CIDR policies. Recommendation is to run 4.11+ kernels.
    HAVE_LRU_MAP_TYPE: Your kernel doesn't support LRU maps for BPF, thus switching back to using hash table for the cilium connection tracker. Recommendation is to run 4.10+ kernels.

Current BPF map state for particular programs is held under ``/sys/fs/bpf/``,
and the `bpf-map <https://github.com/cilium/bpf-map>`_ utility can be useful
for debugging what is going on inside them, for example:

.. code:: bash

    # ls /sys/fs/bpf/tc/globals/
    cilium_calls_15124  cilium_calls_48896        cilium_ct4_global       cilium_lb4_rr_seq       cilium_lb6_services  cilium_policy_25729  cilium_policy_60670       cilium_proxy6
    cilium_calls_25729  cilium_calls_60670        cilium_ct6_global       cilium_lb4_services     cilium_lxc           cilium_policy_3978   cilium_policy_reserved_1  cilium_reserved_policy
    cilium_calls_3978   cilium_calls_netdev_ns_1  cilium_events           cilium_lb6_reverse_nat  cilium_policy        cilium_policy_4314   cilium_policy_reserved_2  cilium_tunnel_map
    cilium_calls_4314   cilium_calls_overlay_2    cilium_lb4_reverse_nat  cilium_lb6_rr_seq       cilium_policy_15124  cilium_policy_48896  cilium_proxy4
    # bpf-map info /sys/fs/bpf/tc/globals/cilium_policy_15124
    Type:           Hash
    Key size:       8
    Value size:     24
    Max entries:    1024
    Flags:          0x0
    # bpf-map dump /sys/fs/bpf/tc/globals/cilium_policy_15124
    Key:
    00000000  6a 01 00 00 82 23 06 00                           |j....#..|
    Value:
    00000000  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    00000010  00 00 00 00 00 00 00 00                           |........|

Update a golang dependency with dep
-----------------------------------

Once you have downloaded dep make sure you have version >= 0.4.1

.. code:: bash

    $ dep version
    dep:
     version     : v0.4.1
     build date  : 2018-01-24
     git hash    : 37d9ea0a
     go version  : go1.9.1
     go compiler : gc
     platform    : linux/amd64

After that, you can edit the ``Gopkg.toml`` file, add the library that you want
to add. Lets assume we want to add ``github.com/containernetworking/cni``
version ``v0.5.2``:

.. code:: bash

    [[constraint]]
      name = "github.com/containernetworking/cni"
      revision = "v0.5.2"

Once you add the libraries that you need you can save the file and run

.. code:: bash

    $ dep ensure -v

For a first run, it can take a while as it will download all dependencies to
your local cache but the remaining runs will be faster.

Update cilium-builder and cilium-runtime images
-----------------------------------------------

Login to quay.io with your credentials to the repository that you want to
update:

`cilium-builder <https://quay.io/repository/cilium/cilium-builder?tab=builds>`__ - contains all envoy dependencies
`cilium-runtime <https://quay.io/repository/cilium/cilium-runtime?tab=builds>`__ - contains all cilium dependencies (excluding envoy dependencies)

0. After login, select the tab "builds" on the left menu.

.. image:: images/cilium-quayio-tag-0.png
    :width: 600px
    :align: center
    :height: 300px

1. Click on the wheel.
2. Enable the trigger for that build trigger.

.. image:: images/cilium-quayio-tag-1.png
    :width: 600px
    :align: center
    :height: 300px

3. Confirm that you want to enable the trigger.

.. image:: images/cilium-quayio-tag-2.png
    :width: 600px
    :align: center
    :height: 300px

4. After enabling the trigger, click again on the wheel.
5. And click on "Run Trigger Now".

.. image:: images/cilium-quayio-tag-3.png
    :width: 600px
    :align: center
    :height: 300px

6. A new pop-up will appear and you can select the branch that contains your
   changes.
7. Select the branch that contains the new changes.

.. image:: images/cilium-quayio-tag-4.png
    :width: 600px
    :align: center
    :height: 300px

8. After selecting your branch click on "Start Build".

.. image:: images/cilium-quayio-tag-5.png
    :width: 600px
    :align: center
    :height: 300px

9. Once the build has started you can disable the Build trigger by clicking on
   the wheel.
10. And click on "Disable Trigger".

.. image:: images/cilium-quayio-tag-6.png
    :width: 600px
    :align: center
    :height: 300px

11. Confirm that you want to disable the build trigger.

.. image:: images/cilium-quayio-tag-7.png
    :width: 600px
    :align: center
    :height: 300px

12. Once the build is finished click under Tags (on the left menu).
13. Click on the wheel and;
14. Add a new tag to the image that was built.

.. image:: images/cilium-quayio-tag-8.png
    :width: 600px
    :align: center
    :height: 300px

15. Write the name of the tag that you want to give for the newly built image.
16. Confirm the name is correct and click on "Create Tag".

.. image:: images/cilium-quayio-tag-9.png
    :width: 600px
    :align: center
    :height: 300px

17. After the new tag was created you can delete the other tag, which is the
    name of your branch. Select the tag name.
18. Click in Actions.
19. Click in "Delete Tags".

.. image:: images/cilium-quayio-tag-10.png
    :width: 600px
    :align: center
    :height: 300px

20. Confirm that you want to delete tag with your branch name.

.. image:: images/cilium-quayio-tag-11.png
    :width: 600px
    :align: center
    :height: 300px

You have created a new image build with a new tag. The next steps should be to
update the repository root's Dockerfile so that it points to the new
``cilium-builder`` or ``cilium-runtime`` image recently created.


Submitting a pull request
-------------------------

Contributions may be submitted in the form of pull requests against the
github repository at: `<https://github.com/cilium/cilium>`_

Before hitting the submit button, please make sure that the following
requirements have been met:

* The pull request and all corresponding commits have been equipped
  with a well written commit message which explains the reasoning
  and details of the change.
* You have added unit and/or runtime tests where feasible.
* You have tested the changes and checked for regressions by running
  the existing testsuite against your changes. See the :ref:`testsuite`
  section for additional details.
* You have signed off on your commits, see the section "Developer's
  Certificate of Origin" for more details.


Triggering Pull-Request Builds With Jenkins
-------------------------------------------

To ensure that build resources are used judiciously, builds on Jenkins
are manually triggered via comments on each pull-request that contain
"trigger-phrases". Only members of the Cilium GitHub organization are
allowed to trigger these jobs. Refer to the table below for information
regarding which phrase triggers which build, which build is required for
a pull-request to be merged, etc. Each linked job contains a description
illustrating which subset of tests the job runs.


+----------------------------------------------------------------------------------------------------------+-------------------+--------------------+
| Jenkins Job                                                                                              | Trigger Phrase    | Required To Merge? |
+==========================================================================================================+===================+====================+
| `Cilium-PR-Ginkgo-Tests-Validated <https://jenkins.cilium.io/job/Cilium-PR-Ginkgo-Tests-Validated/>`_    | test-me-please    | Yes                |
+----------------------------------------------------------------------------------------------------------+-------------------+--------------------+
| `Cilium-Pr-Ginkgo-Test-k8s <https://jenkins.cilium.io/job/Cilium-PR-Ginkgo-Tests-k8s/>`_                 | test-missed-k8s   | No                 |
+----------------------------------------------------------------------------------------------------------+-------------------+--------------------+
| `Cilium-Nightly-Tests-PR <https://jenkins.cilium.io/job/Cilium-PR-Nightly-Tests-All/>`_                  | test-nightly      | No                 |
+----------------------------------------------------------------------------------------------------------+-------------------+--------------------+
| `Cilium-PR-Doc-Tests <https://jenkins.cilium.io/view/all/job/Cilium-PR-Doc-Tests/>`_                     | test-docs-please  | No                 |
+----------------------------------------------------------------------------------------------------------+-------------------+--------------------+
| `Cilium-PR-Kubernetes-Upstream </https://jenkins.cilium.io/view/PR/job/Cilium-PR-Kubernetes-Upstream/>`_ | test-upstream-k8s | No                 |
+----------------------------------------------------------------------------------------------------------+-------------------+--------------------+


There are some feature flags based on Pull Requests labels, the list of labels
are the following:

- area/containerd: Enable containerd runtime on all Kubernetes test.


Using Jenkins for testing
~~~~~~~~~~~~~~~~~~~~~~~~~

Typically when running Jenkins tests via one of the above trigger phases, it
will run all of the tests in that particular category. However, there may be
cases where you just want to run a single test quickly on Jenkins and observe
the test result. To do so, you need to update the relevant test to have a
custom name, and to update the Jenkins file to focus that test. Below is an
example patch that shows how this can be achieved.

.. code-block:: diff

    diff --git a/ginkgo.Jenkinsfile b/ginkgo.Jenkinsfile
    index ee17808748a6..637f99269a41 100644
    --- a/ginkgo.Jenkinsfile
    +++ b/ginkgo.Jenkinsfile
    @@ -62,10 +62,10 @@ pipeline {
                 steps {
                     parallel(
                         "Runtime":{
    -                        sh 'cd ${TESTDIR}; ginkgo --focus="RuntimeValidated*" -v -noColor'
    +                        sh 'cd ${TESTDIR}; ginkgo --focus="XFoooo*" -v -noColor'
                         },
                         "K8s-1.9":{
    -                        sh 'cd ${TESTDIR}; K8S_VERSION=1.9 ginkgo --focus=" K8sValidated*" -v -noColor ${FAILFAST}'
    +                        sh 'cd ${TESTDIR}; K8S_VERSION=1.9 ginkgo --focus=" K8sFooooo*" -v -noColor ${FAILFAST}'
                         },
                         failFast: true
                     )
    diff --git a/test/k8sT/Nightly.go b/test/k8sT/Nightly.go
    index 62b324619797..3f955c73a818 100644
    --- a/test/k8sT/Nightly.go
    +++ b/test/k8sT/Nightly.go
    @@ -466,7 +466,7 @@ var _ = Describe("NightlyExamples", func() {

                    })

    -               It("K8sValidated Updating Cilium stable to master", func() {
    +               FIt("K8sFooooo K8sValidated Updating Cilium stable to master", func() {
                            podFilter := "k8s:zgroup=testapp"

                            //This test should run in each PR for now.

Jenkins Job Descriptions
------------------------

Cilium-PR-Ginkgo-Tests-Validated
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The configuration for this job is contained within ``ginkgo.Jenkinsfile``.

It first runs unit tests using docker-compose using a YAML located at
``test/docker-compose.yaml``.

The next steps happens in parallel:

    - Runs the runtime e2e tests.
    - Runs the Kubernetes e2e tests against the latest default version of Kubernetes specified above.

Cilium-Nightly-Tests-PR
~~~~~~~~~~~~~~~~~~~~~~~

The configuration for this job is contained within ``Jenkinsfile.nightly``.

This first runs the Nightly tests with the following setup:

    - 4 Kubernetes 1.8 nodes
    - 4 GB of RAM per node.
    - 4 vCPUs per node.

Then, it runs tests Kubernetes tests against versions of Kubernetes that are currently not tested against
as part of each pull-request, but that Cilium still supports.

It also runs a variety of tests against Envoy to ensure that proxy functionality is working correctly.

Cilium-PR-Ginkgo-Tests-k8s
~~~~~~~~~~~~~~~~~~~~~~~~~~

Runs the Kubernetes e2e tests against all Kubernetes versions that are not currently not tested as part
of each pull-request, but which Cilium still supports, as well as the the most-recently-released versions
of Kubernetes that are not yet declared stable by Kubernetes upstream:

First stage (stable versions which Cilium still supports):

    - 1.7
    - 1.8

Second stage (unstable versions)

    - 1.10 beta
    - 1.11 alpha

CI / Testing environment
------------------------

Logging into VM running tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. If you have access to credentials for Jenkins, log into the Jenkins slave running the test workload
2. Identify the vagrant box running the specific test

.. code:: bash

    $ vagrant global-status
    id       name                          provider   state   directory
    -------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    6e68c6c  k8s1-build-PR-1588-6          virtualbox running /root/jenkins/workspace/cilium_cilium_PR-1588-CWL743UTZEF6CPEZCNXQVSZVEW32FR3CMGKGY6667CU7X43AAZ4Q/tests/k8s
    ec5962a  cilium-master-build-PR-1588-6 virtualbox running /root/jenkins/workspace/cilium_cilium_PR-1588-CWL743UTZEF6CPEZCNXQVSZVEW32FR3CMGKGY6667CU7X43AAZ4Q
    bfaffaa  k8s2-build-PR-1588-6          virtualbox running /root/jenkins/workspace/cilium_cilium_PR-1588-CWL743UTZEF6CPEZCNXQVSZVEW32FR3CMGKGY6667CU7X43AAZ4Q/tests/k8s
    3fa346c  k8s1-build-PR-1588-7          virtualbox running /root/jenkins/workspace/cilium_cilium_PR-1588-CWL743UTZEF6CPEZCNXQVSZVEW32FR3CMGKGY6667CU7X43AAZ4Q@2/tests/k8s
    b7ded3c  cilium-master-build-PR-1588-7 virtualbox running /root/jenkins/workspace/cilium_cilium_PR-1588-CWL743UTZEF6CPEZCNXQVSZVEW32FR3CMGKGY6667CU7X43AAZ4Q@2

3. Log into the specific VM

.. code:: bash

    $ JOB_BASE_NAME=PR-1588 BUILD_NUMBER=6 vagrant ssh 6e68c6c


Jenkinsfiles Extensions
------------------------
Cilium uses a custom `Jenkins helper library
<https://github.com/cilium/Jenkins-library>`_ to gather metadata from PRs and
simplify our Jenkinsfiles. The exported methods are:

- **ispr()**: return true if the current build is a PR.
- **setIfPr(string, string)**: return the first argument in case of a PR, if not
  a PR return the second one.
- **BuildIfLabel(String label, String Job)**: trigger a new Job if the PR has
  that specific Label.
- **Status(String status, String context)**: set pull request check status on
  the given context, example ``Status("SUCCESS", "$JOB_BASE_NAME")``


Release Process
---------------

Cilium schedules a major release every 3 months. Each major release is
performed by incrementing the ``Y`` in the version format ``X.Y.0``. The group
of committers can decide to increment ``X`` instead to mark major milestones in
which case ``Y`` is reset to 0.

The following steps are performed to publish a release:

1. The master branch is set to the version ``X.Y.90`` at all times. This ensures
   that a development snapshot is considered more recent than a stable release
   at all times.
2. The committers can agree on a series of release candidates which will be
   tagged ``vX.Y-rcN`` in the master branch.
3. The committers declare the master branch ready for the release and fork the
   master branch into a release branch ``vX.Y+1.0``.
4. The first commit in the release branch is to change the version to
   ``X.Y+1.0``.
5. The next commit goes into the master branch and sets the version to
   ``X.Y+1.90`` to ensure that the master branch will be considered more recent
   than any stable release of the major release that is about to be published.

Stable releases
~~~~~~~~~~~~~~~

The committers can nominate commits pushed to the master as stable release
candidates in which case they will be backported to previous release branches.
Upon necessity, stable releases are published with the version ``X.Y.Z+1``.

Criteria for the inclusion into stable release branches are:

- Security relevant fixes
- Major bugfixes relevant to the correct operation of Cilium


Steps to release
~~~~~~~~~~~~~~~~

1. Create a new automated build for ``cilium/cilium`` container image tag with
   the full Cilium version on hub.docker.com. Point the automated build to the
   development branch of the to be released version. This will ensure that the
   to be released version always has a corresponding container image tag
   assigned.
2. Update the AUTHORS file by running ``make update-authors``
3. Update the ``cilium_version`` and ``cilium_tag`` variables in
   ``examples/getting-started/Vagrantfile``
4. Review all merged PRs and add ``release-note/*`` labels as necessary.
   A useful query here is ``is:pr is:merged merged:>=2017-12-16``
5. Generate the release notes by running.
   ``git checkout master``, ``cd contrib/release/``,
   ``GITHUB_TOKEN=xxxx ./relnotes --markdown-file=~/NEWS.rst v1.0.0-rc2..``
6. Manually merge the generated file ``~/NEWS.rst`` into ``NEWS.rst`` in the
   Cilium repository and add the title section with the corresponding release
   date.
7. Create a pull request with all changes above, get it merged into the
   development branch of the to be released version.
8. If the release is a new minor version which will receive backports, then
   create a git branch with the name ``vX.Y``. Push this branch to GitHub and
   protect the branch so it can't be pushed to directly to.
9. Tag the release with the full version string ``vX.Y.Z`` and push the tag
   to the git repository.
10. Build all binaries and push them to S3 using ``contrib/release/uploadrev``.
    See the ``README`` in the ``contrib/release`` directory for more information.
11. Create a GitHub release and include the release notes as well as links to
    the binaries.
12. Update the release branch on
    `Jenkins <https://jenkins.cilium.io/job/cilium-ginkgo/job/cilium/>`__ to be tested on
    every change and Nightly.


Backporting process
~~~~~~~~~~~~~~~~~~~

Cilium PRs that are marked with label ``stable/needs-backport`` need to be backported to the stable branch(es), listed below. Following steps summarize the process.

1. Make sure the Github labels are up-to-date, as this process will
   deal with all commits from PRs that have the
   ``stable/needs-backport`` set.  Especially, clear
   ``stable/backport-triage``, ``stable/backport-pending`` and
   ``stable/needs-backport`` labels from PRs that have already been
   backported as indicated by ``stable/backport-done`` label.
   Generally, if a PR has multiple ``backport`` labels set you will
   need to figure out the status of that PR's backport to clean up the
   labels before proceeding.
2. The scripts referred to below need to be run in Linux, they do not
   work on OSX.  You can use the cilium dev VM for this, but you need
   to configure git to have your name and email address to be used in
   the commit messages:

.. code-block:: bash

        $ git config --global user.name "John Doe"
        $ git config --global user.email johndoe@example.com

3. Make sure you have your a GitHub developer access token
   available. For details, see `contrib/backporting/README.md
   <https://github.com/cilium/cilium/blob/master/contrib/backporting/README.md>`_
4. Fetch the repo, e.g., ``git fetch``
5. Check out the stable branch you are backporting to, e.g., ``git
   checkout v1.0``
6. Create a new branch for your backports, e.g., ``git branch
   v1.0-backports-YY-MM-DD``
7. Check out your backports branch, e.g., ``git checkout v1.0-backports-YY-MM-DD``
8. Run the ``check-stable`` script, referring to your Github access
   token, this will list the commits that need backporting, from the
   newest to oldest:

.. code-block:: bash

        $ GITHUB_TOKEN=xxx contrib/backporting/check-stable

9. Cherry-pick the commits using the master git SHAs listed, starting
   from the oldest (bottom), working your way up and fixing any merge
   conflicts as they appear. Note that for PRs that have multiple
   commits you will want to check that you are cherry-picking oldest
   commits first.

.. code-block:: bash

        $ contrib/backporting/cherry-pick <oldest-commit-sha>
        ...
        $ contrib/backporting/cherry-pick <newest-commit-sha>

10. Push your backports branch to cilium repo, e.g., ``git push -u
    origin v1.0-backports-YY-MM-DD``
11. In Github, create a new PR from you branch towards the feature
    branch you are backporting to. Note that by default Github creates
    PRs against the master branch, so you will need to change it.
12. Label the new backport PR as ``stable/backport`` so that it is
    easy to find backport PRs later.
13. Mark all PRs you backported with ``stable/backport-pending`` label
    and clear the ``stable/needs-backport`` label.  Note that using
    the GitHub web interface it is better to add new labels first so
    that you can still find the PRs using either the new or old label!
14. After the backport PR is merged, mark all backported PRs with
    ``stable/backport-done`` label and clear the
    ``stable/backport-pending`` label.

Stable branches
~~~~~~~~~~~~~~~
- `v1.0 <https://github.com/cilium/cilium/tree/v1.0>`__

Developer's Certificate of Origin
---------------------------------

To improve tracking of who did what, we've introduced a "sign-off"
procedure.

The sign-off is a simple line at the end of the explanation for the
commit, which certifies that you wrote it or otherwise have the right to
pass it on as open-source work. The rules are pretty simple: if you can
certify the below:

::

    Developer Certificate of Origin
    Version 1.1

    Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
    1 Letterman Drive
    Suite D4700
    San Francisco, CA, 94129

    Everyone is permitted to copy and distribute verbatim copies of this
    license document, but changing it is not allowed.


    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.

then you just add a line saying:

::

   Signed-off-by: Random J Developer <random@developer.example.org>

Use your real name (sorry, no pseudonyms or anonymous contributions.)

.. toctree::

   commit-access


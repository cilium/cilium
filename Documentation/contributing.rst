.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _dev_guide:

Developer / Contributor Guide
=============================

We're happy you're interested in contributing to the Cilium project.

This guide will help you make sure you have an environment capable of testing
changes to the Cilium source code, and that you understand the workflow of getting
these changes reviewed and merged upstream.

.. _dev_env:

Setting up the development environment
--------------------------------------

Requirements
~~~~~~~~~~~~

You need to have the following tools available in order to effectively
contribute to Cilium:

+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
| Dependency                                                                       | Version / Commit ID      | Download Command                                                              |
+==================================================================================+==========================+===============================================================================+
| git                                                                              | latest                   | N/A (OS-specific)                                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
|  glibc-devel (32-bit)                                                            | latest                   | N/A (OS-specific)                                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
| `go <https://golang.org/dl/>`_                                                   | 1.11                     | N/A (OS-specific)                                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
| `dep <https://github.com/golang/dep/>`_                                          | >= v0.4.1                | ``curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh``  |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
| `go-bindata <https://github.com/cilium/go-bindata>`_                             | ``a0ff2567cfb``          | ``go get -u github.com/cilium/go-bindata/...``                                |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `ginkgo <https://github.com/onsi/ginkgo>`__                                      | >= 1.4.0                 | ``go get -u github.com/onsi/ginkgo/ginkgo``                                   |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `gomega <https://github.com/onsi/gomega>`_                                       | >= 1.2.0                 | ``go get -u github.com/onsi/gomega``                                          |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `ineffassign <https://github.com/gordonklaus/ineffassign>`_                      | >= ``1003c8b``           | ``go get -u github.com/gordonklaus/ineffassign``                              |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `Docker <https://docs.docker.com/engine/installation/>`_                         | OS-Dependent             | N/A (OS-specific)                                                             |
+----------------------------------------------------------------------------------+--------------------------+-------------------------------------------------------------------------------+
+ `Docker-Compose <https://docs.docker.com/compose/install/>`_                     | OS-Dependent             | N/A (OS-specific)                                                             |
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

If you want to connect to the Kubernetes cluster running inside the developer VM via ``kubectl`` from your host machine, set ``KUBECONFIG`` environment variable to include new kubeconfig file:

::

$ export KUBECONFIG=$KUBECONFIG:$GOPATH/src/github.com/cilium/cilium/vagrant.kubeconfig

and add ``127.0.0.1 k8s1`` to your hosts file.

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
of ports open. The Vagrantfile will inform you of the configuration of these addresses
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

.. _packer_ci:

Packer-CI-Build
^^^^^^^^^^^^^^^

As part of Cilium development, we use a custom base box with a bunch of
pre-installed libraries and tools that we need to enhance our daily workflow.
That base box is built with `Packer <https://www.packer.io/>`_ and it is hosted
in the `packer-ci-build
<https://jenkins.cilium.io/job/Vagrant-Master-Boxes-Packer-Build/>`_ GitHub
repository.

New versions of this box can be created via `Jenkins Packer Build
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

Development process
-------------------

Local Development in Vagrant Box
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

See :ref:`dev_env` for information on how to setup the development environment.

When the development VM is provisioned, it builds and installs Cilium.  After
the initial build and install you can do further building and testing
incrementally inside the VM. ``vagrant ssh`` takes you to the Cilium source
tree directory (``/home/vagrant/go/src/github.com/cilium/cilium``) by default,
and the following commands assume that you are working within that directory.

Build Cilium
^^^^^^^^^^^^

Assuming you have synced (rsync) the source tree after you have made changes,
or the tree is automatically in sync via NFS or guest additions folder sharing,
you can issue a build as follows:

::

    $ make

Install to dev environment
^^^^^^^^^^^^^^^^^^^^^^^^^^

After a successful build and test you can re-install Cilium by:

::

    $ sudo -E make install

Restart Cilium service
^^^^^^^^^^^^^^^^^^^^^^

To run the newly installed version of Cilium, restart the service:

::

    $ sudo systemctl restart cilium

You can verify the service and cilium-agent status by the following
commands, respectively:

::

    $ sudo systemctl status cilium
    $ cilium status

Making Changes
~~~~~~~~~~~~~~

#. Create a topic branch: ``git checkout -b myBranch master``
#. Make the changes you want
#. Separate the changes into logical commits.

   #. Describe the changes in the commit messages. Focus on answering the
      question why the change is required and document anything that might be
      unexpected.
   #. If any description is required to understand your code changes, then
      those instructions should be code comments instead of statements in the
      commit description.
#. Make sure your changes meet the following criteria:

   #. New code is covered by :ref:`unit_testing`.
   #. End to end integration / runtime tests have been extended or added. If
      not required, mention in the commit message what existing test covers the
      new code.
   #. Follow-up commits are squashed together nicely. Commits should separate
      logical chunks of code and not represent a chronological list of changes.
#. Run ``git diff --check`` to catch obvious white space violations
#. Run ``make`` to build your changes. This will also run ``go fmt`` and error out
   on any golang formatting errors.
#. See :ref:`unit_testing` on how to run unit tests.
#. See :ref:`testsuite` for information how to run the end to end integration
   tests

.. _unit_testing:

Unit Testing
~~~~~~~~~~~~

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

Add/update a golang dependency
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

Debugging
~~~~~~~~~

Datapath code
^^^^^^^^^^^^^

The tool ``cilium monitor`` can also be used to retrieve debugging information
from the BPF based datapath. Debugging messages are sent if either the
``cilium-agent`` itself or the respective endpoint is in debug mode. The debug
mode of the agent can be enabled by starting ``cilium-agent`` with the option
``--debug`` enabled or by running ``cilium config debug=true`` for an already
running agent. Debugging of an individual endpoint can be enabled by running
``cilium endpoint config ID debug=true``


.. code:: bash

    $ cilium endpoint config 3978 debug=true
    Endpoint 3978 configuration updated successfully
    $ cilium monitor -v --hex
    Listening for events on 2 CPUs with 64x4096 of shared memory
    Press Ctrl-C to quit
    ------------------------------------------------------------------------------
    CPU 00: MARK 0x1c56d86c FROM 3978 DEBUG: 70 bytes Incoming packet from container ifindex 85
    00000000  33 33 00 00 00 02 ae 45  75 73 11 04 86 dd 60 00  |33.....Eus....`.|
    00000010  00 00 00 10 3a ff fe 80  00 00 00 00 00 00 ac 45  |....:..........E|
    00000020  75 ff fe 73 11 04 ff 02  00 00 00 00 00 00 00 00  |u..s............|
    00000030  00 00 00 00 00 02 85 00  15 b4 00 00 00 00 01 01  |................|
    00000040  ae 45 75 73 11 04 00 00  00 00 00 00              |.Eus........|
    CPU 00: MARK 0x1c56d86c FROM 3978 DEBUG: Handling ICMPv6 type=133
    ------------------------------------------------------------------------------
    CPU 00: MARK 0x1c56d86c FROM 3978 Packet dropped 131 (Invalid destination mac) 70 bytes ifindex=0 284->0
    00000000  33 33 00 00 00 02 ae 45  75 73 11 04 86 dd 60 00  |33.....Eus....`.|
    00000010  00 00 00 10 3a ff fe 80  00 00 00 00 00 00 ac 45  |....:..........E|
    00000020  75 ff fe 73 11 04 ff 02  00 00 00 00 00 00 00 00  |u..s............|
    00000030  00 00 00 00 00 02 85 00  15 b4 00 00 00 00 01 01  |................|
    00000040  00 00 00 00                                       |....|
    ------------------------------------------------------------------------------
    CPU 00: MARK 0x7dc2b704 FROM 3978 DEBUG: 86 bytes Incoming packet from container ifindex 85
    00000000  33 33 ff 00 8a d6 ae 45  75 73 11 04 86 dd 60 00  |33.....Eus....`.|
    00000010  00 00 00 20 3a ff fe 80  00 00 00 00 00 00 ac 45  |... :..........E|
    00000020  75 ff fe 73 11 04 ff 02  00 00 00 00 00 00 00 00  |u..s............|
    00000030  00 01 ff 00 8a d6 87 00  20 40 00 00 00 00 fd 02  |........ @......|
    00000040  00 00 00 00 00 00 c0 a8  21 0b 00 00 8a d6 01 01  |........!.......|
    00000050  ae 45 75 73 11 04 00 00  00 00 00 00              |.Eus........|
    CPU 00: MARK 0x7dc2b704 FROM 3978 DEBUG: Handling ICMPv6 type=135
    CPU 00: MARK 0x7dc2b704 FROM 3978 DEBUG: ICMPv6 neighbour soliciation for address b21a8c0:d68a0000


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

* 1.8
* 1.9
* 1.10
* 1.11
* 1.12
* 1.13

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
      -cilium.testScope string
            Specifies scope of test to be ran (k8s, Nightly, runtime)
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

+----------------------+-------------------+--------------+------------------------------------------------------------------+
| ENV variable         | Default Value     | Options      | Description                                                      |
+======================+===================+==============+==================================================================+
| K8S\_NODES           | 2                 | 0..100       | Number of Kubernetes nodes in the cluster                        |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| NFS                  | 0                 | 1            | If Cilium folder needs to be shared using NFS                    |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| IPv6                 | 0                 | 0-1          | If 1 the Kubernetes cluster will use IPv6                        |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| CONTAINER\_RUNTIME   | docker            | containerd   | To set the default container runtime in the Kubernetes cluster   |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| K8S\_VERSION         | 1.10              | 1.\*\*       | Kubernetes version to install                                    |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| SERVER\_BOX          | cilium/ubuntu-dev | *            | Vagrantcloud base image                                          |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| CPU                  | 2                 | 0..100       | Number of CPUs that need to have the VM                          |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| MEMORY               | 4096              | \d+          | RAM size in Megabytes                                            |
+----------------------+-------------------+--------------+------------------------------------------------------------------+

Further Assistance
~~~~~~~~~~~~~~~~~~

Have a question about how the tests work or want to chat more about improving the
testing infrastructure for Cilium? Hop on over to the
`testing <https://cilium.slack.com/messages/C7PE7V806>`_ channel on Slack.

.. _howto_contribute:

How to contribute
-----------------

Getting Started
~~~~~~~~~~~~~~~

#. Make sure you have a `GitHub account <https://github.com/signup/free>`_
#. Clone the cilium repository

   ::

      go get -d github.com/cilium/cilium
      cd $GOPATH/src/github.com/cilium/cilium

#. Set up your :ref:`dev_env`
#. Check the GitHub issues for `good tasks to get started
   <https://github.com/cilium/cilium/issues?q=is%3Aopen+is%3Aissue+label%3Agood-first-issue>`_.

.. _submit_pr:

Submitting a pull request
~~~~~~~~~~~~~~~~~~~~~~~~~

Contributions must be submitted in the form of pull requests against the github
repository at: `<https://github.com/cilium/cilium>`_

#. Fork the Cilium repository to your own personal GitHub space or request
   access to a Cilium developer account on Slack
#. Push your changes to the topic branch in your fork of the repository.
#. Submit a pull request on https://github.com/cilium/cilium.

Before hitting the submit button, please make sure that the following
requirements have been met:

#. Each commit compiles and is functional on its own to allow for bisecting of
   commits.
#. All code is covered by unit and/or runtime tests where feasible.
#. All changes have been tested and checked for regressions by running the
   existing testsuite against your changes. See the :ref:`testsuite` section
   for additional details.
#. All commits contain a well written commit description including a title,
   description and a ``Fixes: #XXX`` line if the commit addresses a particular
   GitHub issue. Note that the GitHub issue will be automatically closed when
   the commit is merged.

   ::

        apipanic: Log stack at debug level

        Previously, it was difficult to debug issues when the API panicked
        because only a single line like the following was printed:

        level=warning msg="Cilium API handler panicked" client=@ method=GET
        panic_message="write unix /var/run/cilium/cilium.sock->@: write: broken
        pipe"

        This patch logs the stack at this point at debug level so that it can at
        least be determined in developer environments.

        Fixes: #4191

        Signed-off-by: Joe Stringer <joe@covalent.io>

   .. note:

       Make sure to include a blank line in between commit title and commit
       description.

#. If any of the commits fixes a particular commit already in the tree, that
   commit is referenced in the commit message of the bugfix. This ensures that
   whoever performs a backport will pull in all required fixes:

   ::

      daemon: use endpoint RLock in HandleEndpoint

      Fixes: a804c7c7dd9a ("daemon: wait for endpoint to be in ready state if specified via EndpointChangeRequest")

      Signed-off-by: André Martins <andre@cilium.io>

   .. note:

      The proper format for the ``Fixes:`` tag referring to commits is to use
      the first 12 characters of the git SHA followed by the full commit title
      as seen above without breaking the line.

#. All commits are signed off. See the section :ref:`dev_coo`.

#. Pick the appropriate milestone for which this PR is being targeted to, e.g.
   ``1.1``, ``1.2``. This is in particular important in the time frame between
   the feature freeze and final release date.

#. Pick the right release-note label

   +--------------------------+---------------------------------------------------------------------------+
   | Labels                   | When to set                                                               |
   +==========================+===========================================================================+
   | ``release-note/bug``     | This is a non-trivial bugfix                                              |
   +--------------------------+---------------------------------------------------------------------------+
   | ``release-note/major``   | This is a major feature addition, e.g. Add MongoDB support                |
   +--------------------------+---------------------------------------------------------------------------+
   | ``release-note/minor``   | This is a minor feature addition, e.g. Refactor endpoint package          |
   +--------------------------+---------------------------------------------------------------------------+

#. Verify the release note text. If not explicitly changed, the title of the PR
   will be used for the release notes. If you want to change this, you can add
   a special section to the description of the PR.

   ::

      ```release-note
      This is a release note text
      ```

   .. note::

      If multiple lines are provided, then the first line serves as the high
      level bullet point item and any additional line will be added as a sub
      item to the first line.

#. Pick the right labels for your PR:

   +------------------------------+---------------------------------------------------------------------------+
   | Labels                       | When to set                                                               |
   +==============================+===========================================================================+
   | ``kind/bug``                 | This is a bugfix worth mentioning in the release notes                    |
   +------------------------------+---------------------------------------------------------------------------+
   | ``kind/enhancement``         | This is an enhancement/feature                                            |
   +------------------------------+---------------------------------------------------------------------------+
   | ``priority/release-blocker`` | This PR should block the current release                                  |
   +------------------------------+---------------------------------------------------------------------------+
   | ``area/*``                   | Code area this PR covers                                                  |
   +------------------------------+---------------------------------------------------------------------------+
   | ``needs-backport/X.Y``       | PR needs to be backported to these stable releases                        |
   +------------------------------+---------------------------------------------------------------------------+
   | ``pending-review``           | PR is immediately ready for review                                        |
   +------------------------------+---------------------------------------------------------------------------+
   | ``wip``                      | PR is still work in progress, signals reviewers to hold.                  |
   +------------------------------+---------------------------------------------------------------------------+
   | ``backport/X.Y``             | This is backport PR, may only be set as part of :ref:`backport_process`   |
   +------------------------------+---------------------------------------------------------------------------+
   | ``upgrade-impact``           | The code changes have a potential upgrade impact                          |
   +------------------------------+---------------------------------------------------------------------------+

   .. note:

      If you do not have permissions to set labels on your pull request. Leave
      a comment and a core team member will add the labels for you. Most
      reviewers will do this automatically without prior request.

Getting a pull request merged
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. As you submit the pull request as described in the section :ref:`submit_pr`.
   One of the reviewers will start a CI run by replying with a comment
   ``test-me-please`` as described in :ref:`trigger_phrases`. If you are a
   core team member, you may trigger the CI run yourself.

   #. Hound: basic ``golang/lint`` static code analyzer. You need to make the
      puppy happy.
   #. :ref:`ci_jenkins`: Will run a series of tests:

      #. Unit tests
      #. Single node runtime tests
      #. Multi node Kubernetes tests

#. As part of the submission, GitHub will have requested a review from the
   respective code owners according to the ``CODEOWNERS`` file in the
   repository.

   #. Address any feedback received from the reviewers
   #. You can push individual commits to address feedback and then rebase your
      branch at the end before merging.

#. Owners of the repository will automatically adjust the labels on the pull
   request to track its state and progress towards merging.
#. Once the PR has been reviewed and the CI tests have passed, the PR will be
   merged by one of the repository owners. In case this does not happen, ping
   us on Slack.


Pull request review process
---------------------------

.. note::

   These instructions assume that whoever is reviewing is a member of the
   Cilium GitHub organization or has the status of a contributor. This is
   required to obtain the privileges to modify GitHub labels on the pull
   request.

#. Review overall correctness of the PR according to the rules specified in the
   section :ref:`submit_pr`.

   Set the label accordingly.


   +--------------------------------+---------------------------------------------------------------------------+
   | Labels                         | When to set                                                               |
   +================================+===========================================================================+
   | ``dont-merge/needs-sign-off``  | Some commits are not signed off                                           |
   +--------------------------------+---------------------------------------------------------------------------+
   | ``needs-rebase``               | PR is outdated and needs to be rebased                                    |
   +--------------------------------+---------------------------------------------------------------------------+

#. As soon as a PR has the label ``pending-review``, review the code and
   request changes as needed by using the GitHub ``Request Changes`` feature or
   by using Reviewable.

#. Validate that bugfixes are marked with ``kind/bug`` and validate whether the
   assessment of backport requirements as requested by the submitter conforms
   to the :ref:`stable_releases` process.


   +--------------------------+---------------------------------------------------------------------------+
   | Labels                   | When to set                                                               |
   +==========================+===========================================================================+
   | ``needs-backport/X.Y``   | PR needs to be backported to these stable releases                        |
   +--------------------------+---------------------------------------------------------------------------+

#. If the PR is subject to backport, validate that the PR does not mix bugfix
   and refactoring of code as it will heavily complicate the backport process.
   Demand for the PR to be split.

#. Validate the ``release-note/*`` label and check the PR title for release
   note suitability. Put yourself into the perspective of a future release
   notes reader with lack of context and ensure the title is precise but brief.

   +-----------------------------------+---------------------------------------------------------------------------+
   | Labels                            | When to set                                                               |
   +===================================+===========================================================================+
   | ``dont-merge/needs-release-note`` | Do NOT merge PR, needs a release note                                     |
   +-----------------------------------+---------------------------------------------------------------------------+
   | ``release-note/bug``              | This is a non-trivial bugfix                                              |
   +-----------------------------------+---------------------------------------------------------------------------+
   | ``release-note/major``            | This is a major feature addition                                          |
   +-----------------------------------+---------------------------------------------------------------------------+
   | ``release-note/minor``            | This is a minor feature addition                                          |
   +-----------------------------------+---------------------------------------------------------------------------+

#. Check for upgrade compatibility impact and if in doubt, set the label
   ``upgrade-impact`` and discuss in the Slack channel.

   +--------------------------+---------------------------------------------------------------------------+
   | Labels                   | When to set                                                               |
   +==========================+===========================================================================+
   | ``upgrade-impact``       | The code changes have a potential upgrade impact                          |
   +--------------------------+---------------------------------------------------------------------------+

#. When everything looks OK, approve the changes.

#. When all review objectives for all ``CODEOWNERS`` are met and all CI tests
   have passed, you may set the ``ready-to-merge`` label to indicate that all
   criteria have been met.

   +--------------------------+---------------------------------------------------------------------------+
   | Labels                   | When to set                                                               |
   +==========================+===========================================================================+
   | ``ready-to-merge``       | PR is ready to be merged                                                  |
   +--------------------------+---------------------------------------------------------------------------+


Documentation
-------------

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

Now the documentation page should be browsable on http://localhost:8080.

.. _ci_jenkins:

CI / Jenkins
------------

The main CI infrastructure is maintained at https://jenkins.cilium.io/

Jobs Overview
~~~~~~~~~~~~~

Cilium-PR-Ginkgo-Tests-Validated
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Runs validated Ginkgo tests which are confirmed to be stable and have been
verified. These tests must always pass.

The configuration for this job is contained within ``ginkgo.Jenkinsfile``.

It first runs unit tests using docker-compose using a YAML located at
``test/docker-compose.yaml``.

The next steps happens in parallel:

    - Runs the single-node e2e tests using the Docker runtime.
    - Runs the multi-node Kubernetes e2e tests against the latest default
      version of Kubernetes specified above.


Cilium-PR-Ginkgo-Tests-k8s
^^^^^^^^^^^^^^^^^^^^^^^^^^

Runs the Kubernetes e2e tests against all Kubernetes versions that are not
currently not tested as part of each pull-request, but which Cilium still
supports, as well as the the most-recently-released versions of Kubernetes that
are not yet declared stable by Kubernetes upstream:

First stage (stable versions which Cilium still supports):

    - 1.8
    - 1.11

Second stage (other versions)

    - 1.9
    - 1.10

Ginkgo-CI-Tests-Pipeline
^^^^^^^^^^^^^^^^^^^^^^^^

https://jenkins.cilium.io/job/Ginkgo-CI-Tests-Pipeline/

Cilium-Nightly-Tests-PR
^^^^^^^^^^^^^^^^^^^^^^^

Runs long-lived tests which take extended time. Some of these tests have an
expected failure rate.

Nightly tests run once per day in the `Cilium-Nightly-Tests Job`_.  The
configuration for this job is stored in ``Jenkinsfile.nightly``.

To see the results of these tests, you can view the JUnit Report for an individual job:

1. Click on the build number you wish to get test results from on the left hand
   side of the `Cilium-Nightly-Tests Job`_.
2. Click on 'Test Results' on the left side of the page to view the results from the build.
   This will give you a report of which tests passed and failed. You can click on each test
   to view its corresponding output created from Ginkgo.

This first runs the Nightly tests with the following setup:

    - 4 Kubernetes 1.8 nodes
    - 4 GB of RAM per node.
    - 4 vCPUs per node.

Then, it runs tests Kubernetes tests against versions of Kubernetes that are currently not tested against
as part of each pull-request, but that Cilium still supports.

It also runs a variety of tests against Envoy to ensure that proxy functionality is working correctly.

.. _trigger_phrases:

Triggering Pull-Request Builds With Jenkins
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

CI Failure Triage
~~~~~~~~~~~~~~~~~

This section describes the process to triage CI failures. We define 3 categories:

+----------------------+-----------------------------------------------------------------------------------+
| Keyword              | Description                                                                       |
+======================+===================================================================================+
| Flake                | Failure due to a temporary situation such as loss of connectivity to external     |
|                      | services or bug in system component, e.g. quay.io is down, VM race conditions,    |
|                      | kube-dns bug, ...                                                                 |
+----------------------+-----------------------------------------------------------------------------------+
| CI-Bug               | Bug in the test itself that renders the test unreliable, e.g. timing issue when   |
|                      | importing and missing to block until policy is being enforced before connectivity |
|                      | is verified.                                                                      |
+----------------------+-----------------------------------------------------------------------------------+
| Regression           | Failure is due to a regression, all failures in the CI that are not caused by     |
|                      | bugs in the test are considered regressions.                                      |
+----------------------+-----------------------------------------------------------------------------------+

Pipelines subject to triage
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Build/test failures for the following Jenkins pipelines must be reported as
GitHub issues using the process below:

+---------------------------------------+------------------------------------------------------------------+
| Pipeline                              | Description                                                      |
+=======================================+==================================================================+
| `Ginkgo-Tests-Validated-master`_      | Runs whenever a PR is merged into master                         |
+---------------------------------------+------------------------------------------------------------------+
| `Ginkgo-Tests-Validated-1.0`_         | Runs standard Ginkgo tests on merge into branch ``v1.0``         |
+---------------------------------------+------------------------------------------------------------------+
| `Ginkgo-CI-Tests-Pipeline`_           | Runs every two hours on the master branch                        |
+---------------------------------------+------------------------------------------------------------------+
| `Master-Nightly-Tests-All`_           | Runs durability tests every night                                |
+---------------------------------------+------------------------------------------------------------------+
| `Vagrant-Master-Boxes-Packer-Build`_  | Runs on merge into `github.com/cilium/packer-ci-build`_.         |
+---------------------------------------+------------------------------------------------------------------+
| `BETA-cilium-v1.1-standard`_          | Runs standard Ginkgo tests on merge into branch ``v1.1``         |
+---------------------------------------+------------------------------------------------------------------+
| `BETA-cilium-v1.1-K8s-all`_           | Runs K8s tests on merge into branch ``v1.1``                     |
+---------------------------------------+------------------------------------------------------------------+
| `BETA-cilium-v1.1-K8s-Upstream`_      | Runs K8s upstream tests on merge into branch ``v1.1``            |
+---------------------------------------+------------------------------------------------------------------+
| `BETA-cilium-v1.1-Docs`_              | Runs docs tests on merge into branch ``v1.1``                    |
+---------------------------------------+------------------------------------------------------------------+
| `BETA-cilium-v1.1-Nightly`_           | Runs durability tests on branch ``v1.1`` every night             |
+---------------------------------------+------------------------------------------------------------------+

.. note::

  ``BETA-cilium-v1.0-*`` is currently not subject to the daily triage process
  as the quality of the tests backported to that branch does not justify the
  effort.

.. _Ginkgo-Tests-Validated-master: https://jenkins.cilium.io/job/cilium-ginkgo/job/cilium/job/master/lastBuild/
.. _Ginkgo-Tests-Validated-1.0: https://jenkins.cilium.io/job/cilium-ginkgo/job/cilium/job/v1.0/lastBuild/
.. _Ginkgo-CI-Tests-Pipeline: https://jenkins.cilium.io/job/Ginkgo-CI-Tests-Pipeline/
.. _Master-Nightly-Tests-All: https://jenkins.cilium.io/job/Cilium-Master-Nightly-Tests-All/
.. _Vagrant-Master-Boxes-Packer-Build: https://jenkins.cilium.io/job/Vagrant-Master-Boxes-Packer-Build/
.. _github.com/cilium/packer-ci-build: https://github.com/cilium/packer-ci-build/
.. _BETA-cilium-v1.1-standard: https://jenkins.cilium.io/view/BETA-Cilium-v1.1/job/BETA-cilium-v1.1-standard/
.. _BETA-cilium-v1.1-K8s-all: https://jenkins.cilium.io/view/BETA-Cilium-v1.1/job/BETA-cilium-v1.1-K8s-all/
.. _BETA-cilium-v1.1-K8s-Upstream: https://jenkins.cilium.io/view/BETA-Cilium-v1.1/job/BETA-cilium-v1.1-K8s-Upstream/
.. _BETA-cilium-v1.1-Nightly: https://jenkins.cilium.io/view/BETA-Cilium-v1.1/job/BETA-cilium-v1.1-Nightly/
.. _BETA-cilium-v1.1-Docs: https://jenkins.cilium.io/view/BETA-Cilium-v1.1/job/BETA-cilium-v1.1-Docs/

Triage process
^^^^^^^^^^^^^^

#. Discover untriaged Jenkins failures via the jenkins-failures.sh script. It
   defaults to checking the previous 24 hours but this can be modified by
   setting the SINCE environment variable (it is a unix timestamp). The script
   checks the various test pipelines that need triage.

   .. code-block:: bash

       $ contrib/scripts/jenkins-failures.sh

  .. note::

     You can quickly assign SINCE with statements like ``SINCE=`date -d -3days```

#. Investigate the failure you are interested in and determine if it is a
   CI-Bug, Flake, or a Regression as defined in the table above.

   #. Search `GitHub issues <https://github.com/cilium/cilium/issues?utf8=%E2%9C%93&q=is%3Aissue+>`_
      to see if bug is already filed. Make sure to also include closed issues in
      your search as a CI issue can be considered solved and then re-appears.
      Good search terms are:

      - The test name, e.g.
        ::

            k8s-1.7.K8sValidatedKafkaPolicyTest Kafka Policy Tests KafkaPolicies (from (k8s-1.7.xml))

      - The line on which the test failed, e.g.
        ::

            github.com/cilium/cilium/test/k8sT/KafkaPolicies.go:202

      - The error message, e.g.
        ::

            Failed to produce from empire-hq on topic deathstar-plan

#. If a corresponding GitHub issue exists, update it with:

   #. A link to the failing Jenkins build (note that the build information is
      eventually deleted).
   #. Attach the zipfile downloaded from Jenkins with logs from the failing
      tests. A zipfile for all tests is also available.
   #. Check how much time has passed since the last reported occurrence of this
      failure and move this issue to the correct column in the `CI flakes
      project <https://github.com/cilium/cilium/projects/8>`_ board.

#. If no existing GitHub issue was found, file a `new GitHub issue <https://github.com/cilium/cilium/issues/new>`_:

   #. Attach zipfile downloaded from Jenkins with logs from failing test
   #. If the failure is a new regression or a real bug:

      #. Title: ``<Short bug description>``
      #. Labels ``kind/bug`` and ``needs/triage``.

   #. If failure is a new CI-Bug, Flake or if you are unsure:

      #. Title ``CI: <testname>: <cause>``, e.g. ``CI: K8sValidatedPolicyTest Namespaces: cannot curl service``
      #. Labels ``kind/bug/CI`` and ``needs/triage``
      #. Include a link to the failing Jenkins build (note that the build information is
         eventually deleted).
      #. Attach zipfile downloaded from Jenkins with logs from failing test
      #. Include the test name and whole Stacktrace section to help others find this issue.
      #. Add issue to `CI flakes project <https://github.com/cilium/cilium/projects/8>`_

   .. note::

      Be extra careful when you see a new flake on a PR, and want to open an
      issue. It's much more difficult to debug these without context around the
      PR and the changes it introduced. When creating an issue for a PR flake,
      include a description of the code change, the PR, or the diff. If it
      isn't related to the PR, then it should already happen in master, and a
      new issue isn't needed. 

#. Edit the description of the Jenkins build to mark it as triaged. This will
   exclude it from future jenkins-failures.sh output.

   #. Login -> Click on build -> Edit Build Information
   #. Add the failure type and GH issue number. Use the table describing the
      failure categories, at the beginning of this section, to help
      categorize them.

   .. note::

      This step can only be performed with an account on Jenkins. If you are
      interested in CI failure reviews and do not have an account yet, ping us
      on Slack.

**Examples:**

* ``Flake, quay.io is down``
* ``Flake, DNS not ready, #3333``
* ``CI-Bug, K8sValidatedPolicyTest: Namespaces, pod not ready, #9939``
* ``Regression, k8s host policy, #1111``

Infrastructure details
~~~~~~~~~~~~~~~~~~~~~~

Logging into VM running tests
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^

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


Release Management
------------------

This section describes the release cadence and all release related processes.

Release Cadence
~~~~~~~~~~~~~~~

Cilium schedules a minor release every 6 weeks. Each minor release is performed
by incrementing the ``Y`` in the version format ``X.Y.Z``. The group of
committers can decide to increment ``X`` instead to mark major milestones in
which case ``Y`` is reset to 0.

.. _stable_releases:

Stable releases
~~~~~~~~~~~~~~~

The committers can nominate PRs merged into master as required for backport
into the stable release branches. Upon necessity, stable releases are published
with the version ``X.Y.Z+1``. Stable releases are regularly released in high
frequency or on demand to address major incidents.

In order to guarantee stable production usage while maintaining a high release
cadence, the following stable releases will be maintained:

* Stable backports into the last two releases
* :ref:`lts` release for extended long term backport coverage


Backport criteria for X.Y.Z+n
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Criteria for the inclusion into latest stable release branch, i.e. what goes
into ``v1.1.x`` before ``v1.2.0`` has been released:

- All bugfixes

Backport criteria for X.Y-1.Z
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Criteria for the inclusion into the stable release branch of the previous
release, i.e. what goes into ``v1.0.x``, before ``v1.2.0`` has been released:

- Security relevant fixes
- Major bugfixes relevant to the correct operation of Cilium

.. _lts:

LTS
~~~

The group of committers nominates a release to be a long term stable release.
Such releases are guaranteed to receive backports for major and security
relevant bugfixes. LTS releases will be declared end of life after 6 months.
The group of committers will nominate and start supporting a new LTS release
before the current LTS expires. If for some reason, no release can be declared
LTS before the current LTS release expires, the current LTS lifetime will be
extended.

Given the current 6 weeks release cadence, the development teams will aim at
declaring every 3rd release to be an LTS to guarantee enough time overlap
between LTS release.

Current LTS releases
^^^^^^^^^^^^^^^^^^^^

+----------------------+---------------------------+-----------------------+
| Release              | Original Release Date     | Scheduled End of Life |
+======================+===========================+=======================+
| 1.0                  | 2018-04-24                | 2018-10-24            |
+----------------------+---------------------------+-----------------------+

.. _generic_release_process:

Generic Release Process
~~~~~~~~~~~~~~~~~~~~~~~

This process applies to all releases other than minor releases, this includes:

* Stable releases
* Release candidates

If you intent to release a new minor release, see the
:ref:`minor_release_process` section instead.

.. note:: The following commands have been validated when ran in the VM
          used in the Cilium development process. See :ref:`dev_env` for
          detailed instructions about setting up said VM.

#. Ensure that the necessary backports have been completed and merged. See
   :ref:`backport_process`.
#. Checkout the desired stable branch and pull it:

   ::

       git checkout v1.0; git pull

#. Create a branch for the release pull request:

   ::

       git checkout -b pr/prepare-v1.0.3

#. Update the ``VERSION`` file to represent ``X.Y.Z+1``
#. If this is the first release after creating a new release branch. Adjust the
   image pull policy for all ``.sed`` files in ``examples/kubernetes`` from
   ``Always`` to ``IfNotPresent``.
#. Update the image tag versions in the examples:

   ::

       make -C examples/kubernetes clean all

#. Update the ``cilium_version`` and ``cilium_tag`` variables in
   ``examples/getting-started/Vagrantfile``

#. Update the ``AUTHORS file``

   ::

       make update-authors


   .. note:: 
       
       Check to see if the ``AUTHORS`` file has any formatting errors (for
       instance, indentation mismatches) as well as duplicate contributor
       names, and correct them accordingly.


#. Generate the ``NEWS.rst`` addition based off of the prior release tag
   (e.g., if you are generating the ``NEWS.rst`` for v1.0.3):

   ::

       git shortlog v1.0.2.. > add-to-NEWS.rst

#. Add a new section to ``NEWS.rst``:

    ::

        v1.0.3
        ======

        ::

            <<contents of add-to-NEWS.rst>>
            [...]
            <<end of add-to-NEWS.rst>>

#. Add all modified files using ``git add`` and create a pull request with the
   title ``Prepare for release v1.0.3``. Add the backport label to the PR which
   corresponds to the branch for which the release is being performed, e.g.
   ``backport/1.0``.

   .. note::

       Make sure to create the PR against the desired stable branch. In this
       case ``v1.0``


#. Follow standard procedures to get the aforementioned PR merged into the 
   desired stable branch. See :ref:`submit_pr` for more information about this
   process.

#. Checkout out the stable branch and pull your merged changes:

   ::

       git checkout v1.0; git pull

#. Create release tags:

   ::

       git tag -a v1.0.3 -m 'Release v1.0.3'
       git tag -a 1.0.3 -m 'Release 1.0.3'

   .. note::

       There are two tags that correspond to the same release because GitHub
       recommends using ``vx.y.z`` for release version formatting, and ReadTheDocs,
       which hosts the Cilium documentation, requires the version to be in format
       ``x.y.z`` For more information about how ReadTheDocs does versioning, you can
       read their `Versions Documentation <https://docs.readthedocs.io/en/latest/versions.html>`_.

#. Build the binaries and push it to the release bucket:

   ::

       DOMAIN=releases.cilium.io ./contrib/release/uploadrev v1.0.3


   This step will print a markdown snippet which you will need when crafting
   the GitHub release so make sure to keep it handy.

   .. note:

       This step requires valid AWS credentials to be available via the
       environment variables ``AWS_ACCESS_KEY_ID`` and
       ``AWS_SECRET_ACCESS_KEY``. Ping in the ``#development`` channel on Slack
       if you have no access. It also requires the aws-cli tools to be installed.

#. Build the container images and push them

   ::

      DOCKER_IMAGE_TAG=v1.0.3 make docker-image
      docker push cilium/cilium:v1.0.3

   .. note:

      This step requires you to login with ``docker login`` first and it will
      require your Docker hub ID to have access to the ``Cilium`` organization.
      You can alternatively trigger a build on DockerHub directly if you have
      credentials to do so.

#. Push the git release tag

   ::

       git push --tags

#. `Create a GitHub release <https://github.com/cilium/cilium/releases/new>`_:

   #. Choose the correct target branch, e.g. ``v1.0``
   #. Choose the correct target tag, e.g. ``v1.0.3``
   #. Title: ``1.0.3``
   #. Check the ``This is a pre-release`` box if you are releasing a release
      candidate.
   #. Fill in the release description:

      ::

           Changes
           -------

           ```
           << contents of NEWS.rst for this release >>
           ```

           Release binaries
           ----------------

           << contents of snippet outputed by uploadrev >>

   #. Preview the description and then publish the release

#. Announce the release in the ``#general`` channel on Slack

#. Bump the version of Cilium used in the Cilium upgrade tests to use the new release

   Please reach out on the ``#development`` channel on Slack for assistance with
   this task.


.. _minor_release_process:

Minor Release Process
~~~~~~~~~~~~~~~~~~~~~

On Freeze date
^^^^^^^^^^^^^^

#. Fork a new release branch from master:

   ::

       git checkout master; git pull
       git checkout -b v1.2
       git push

#. Protect the branch using the GitHub UI to disallow direct push and require
   merging via PRs with proper reviews.

#. Replace the contents of the ``CODEOWNERS`` file with the following to reduce
   code reviews to essential approvals:

   ::

        * @cilium/janitors
        api/ @cilium/api
        pkg/apisocket/ @cilium/api
        pkg/monitor/payload @cilium/api
        pkg/policy/api/ @cilium/api
        pkg/proxy/accesslog @cilium/api

#. Commit changes, open a pull request against the new ``v1.2`` branch, and get
   the pull request merged

   ::

       git checkout -b pr/prepare-v1.2
       git add [...]
       git commit
       git push

#. Follow the :ref:`generic_release_process` to release ``v1.2.0-rc1``.

#. Create the following GitHub labels:

   #. ``backport-pending/1.2``
   #. ``backport-done/1.2``
   #. ``backport/1.2``
   #. ``needs-backport/1.2``

#. Prepare the master branch for the next development cycle:

   ::

       git checkout master; git pull

#. Update the ``VERSION`` file to contain ``v1.2.90``
#. Add the ``VERSION`` file using ``git add`` and create & merge a PR titled
   ``Prepare for 1.3.0 development``.
#. Update the release branch on
    `Jenkins <https://jenkins.cilium.io/job/cilium-ginkgo/job/cilium/>`_ to be
    tested on every change and Nightly.
#. (Only 1.0 minor releases) Tag newest 1.0.x Docker image as ``v1.0-stable``
   and push it to Docker Hub. This will ensure that Kops uses latest 1.0 release by default.



For the final release
^^^^^^^^^^^^^^^^^^^^^

#. Follow the :ref:`generic_release_process` to create the final replace and replace
   ``X.Y.0-rcX`` with ``X.Y.0``.

.. _backport_process:

Backporting process
~~~~~~~~~~~~~~~~~~~

Cilium PRs that are marked with the label ``needs-backport/X.Y`` need to be
backported to the stable branch ``X.Y``. The following steps summarize
the process for backporting these PRs.

1. Make sure the Github labels are up-to-date, as this process will
   deal with all commits from PRs that have the ``needs-backport/X.Y`` label
   set (for a stable release version X.Y). If any PRs contain labels such as
   ``backport-pending/X.Y``, ensure that the backport for that PR have been
   merged and if so, change the label to ``backport-done/X.Y``.

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
5. Check a new branch for your backports based on the stable branch for that
   version, e.g., ``git checkout -b pr/v1.0-backport-YY-MM-DD origin/v1.0``
6. Run the ``check-stable`` script, referring to your Github access
   token, this will list the commits that need backporting, from the
   newest to oldest:

.. code-block:: bash

        $ GITHUB_TOKEN=xxx contrib/backporting/check-stable 1.0

7. Cherry-pick the commits using the master git SHAs listed, starting
   from the oldest (bottom), working your way up and fixing any merge
   conflicts as they appear. Note that for PRs that have multiple
   commits you will want to check that you are cherry-picking oldest
   commits first.

.. code-block:: bash

        $ contrib/backporting/cherry-pick <oldest-commit-sha>
        ...
        $ contrib/backporting/cherry-pick <newest-commit-sha>

8. Push your backports branch to cilium repo, e.g., ``git push -u origin pr/v1.0-backports-YY-MM-DD``
9. In Github, create a new PR from your branch towards the feature
   branch you are backporting to. Note that by default Github creates
   PRs against the master branch, so you will need to change it.
10. Label the new backport PR with the backport label for the stable branch
    such as ``backport/X.Y`` so that it is easy to find backport PRs later.
11. Mark all PRs you backported with the backport pending label ``backport-pending/X.Y``
    and clear the ``needs-backport/vX.Y`` label. This can be via the GitHub
    interface, or using the backport script ``contrib/backporting/set-labels.py``, e.g.:

    .. code-block:: bash

        # Set PR 1234's v1.0 backporting labels to pending
        $ contrib/backporting/set-labels.py 1234 pending 1.0

    .. note::

        ``contrib/backporting/set-labels.py`` requires Python 3 and
        `PyGithub <https://pypi.org/project/PyGithub/>`_ installed.

12. After the backport PR is merged, mark all backported PRs with
    ``backport-done/X.Y`` label and clear the ``backport-pending/X.Y`` label(s).

    .. code-block:: bash

        # Set PR 1234's v1.0 backporting labels to done
        contrib/backporting/set-labels.py 1234 done 1.0.

Update cilium-builder and cilium-runtime images
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Login to quay.io with your credentials to the repository that you want to
update:

`cilium-builder <https://quay.io/repository/cilium/cilium-builder?tab=builds>`__ - contains Cilium build-time dependencies
`cilium-runtime <https://quay.io/repository/cilium/cilium-runtime?tab=builds>`__ - contains Cilium run-time dependencies

0. After login, select the tab "builds" on the left menu.

.. image:: images/cilium-quayio-tag-0.png
    :align: center

1. Click on the wheel.
2. Enable the trigger for that build trigger.

.. image:: images/cilium-quayio-tag-1.png
    :align: center

3. Confirm that you want to enable the trigger.

.. image:: images/cilium-quayio-tag-2.png
    :align: center

4. After enabling the trigger, click again on the wheel.
5. And click on "Run Trigger Now".

.. image:: images/cilium-quayio-tag-3.png
    :align: center

6. A new pop-up will appear and you can select the branch that contains your
   changes.
7. Select the branch that contains the new changes.

.. image:: images/cilium-quayio-tag-4.png
    :align: center

8. After selecting your branch click on "Start Build".

.. image:: images/cilium-quayio-tag-5.png
    :align: center

9. Once the build has started you can disable the Build trigger by clicking on
   the wheel.
10. And click on "Disable Trigger".

.. image:: images/cilium-quayio-tag-6.png
    :align: center

11. Confirm that you want to disable the build trigger.

.. image:: images/cilium-quayio-tag-7.png
    :align: center

12. Once the build is finished click under Tags (on the left menu).
13. Click on the wheel and;
14. Add a new tag to the image that was built.

.. image:: images/cilium-quayio-tag-8.png
    :align: center

15. Write the name of the tag that you want to give for the newly built image.
16. Confirm the name is correct and click on "Create Tag".

.. image:: images/cilium-quayio-tag-9.png
    :align: center

17. After the new tag was created you can delete the other tag, which is the
    name of your branch. Select the tag name.
18. Click in Actions.
19. Click in "Delete Tags".

.. image:: images/cilium-quayio-tag-10.png
    :align: center

20. Confirm that you want to delete tag with your branch name.

.. image:: images/cilium-quayio-tag-11.png
    :align: center

You have created a new image build with a new tag. The next steps should be to
update the repository root's Dockerfile so that it points to the new
``cilium-builder`` or ``cilium-runtime`` image recently created.

21. Update the versions of the images that are pulled into the CI VMs.

* Open a PR against the :ref:`packer_ci` with an update to said image versions. Once your PR is merged, a new version of the VM will be ready for consumption in the CI.
* Update the ``SERVER_VERSION``  field in ``test/Vagrantfile`` to contain the new version, which is the build number from the `Jenkins Job for the VMs <https://jenkins.cilium.io/job/Vagrant-Master-Boxes-Packer-Build/>`_. For example, build 119 from the pipeline would be the value to set for ``SERVER_VERSION``. 
* Open a pull request with this version change in the cilium repository.


Nightly Docker image
~~~~~~~~~~~~~~~~~~~~

After each successful Nightly build, a `cilium/nightly`_ image is pushed to dockerhub.

To use latest nightly build, please use ``cilium/nightly:latest`` tag.
Nightly images are stored on dockerhub tagged with following format: ``YYYYMMDD-<job number>``.
Job number is added to tag for the unlikely event of two consecutive nightly builds being built on the same date.


.. _dev_coo:

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

.. _cilium/nightly: https://hub.docker.com/r/cilium/nightly/
.. _Cilium-Nightly-Tests Job: https://jenkins.cilium.io/job/Cilium-Master-Nightly-Tests-All/

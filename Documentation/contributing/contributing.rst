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
| `go <https://golang.org/dl/>`_                                                   | 1.12                     | N/A (OS-specific)                                                             |
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
* ``VM_SET_PROXY=https://127.0.0.1:80/`` Sets up VM's ``https_proxy``.

If you want to start the VM with cilium enabled with ``containerd``, with
kubernetes installed and plus a worker, run:

::

	$ RUNTIME=containerd K8S=1 NWORKERS=1 contrib/vagrant/start.sh

If you want to get VM status, run:
::

  $ RUNTIME=containerd K8S=1 NWORKERS=1 vagrant status

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

Make sure that you update vagrant box versions in `test Vagrantfile <https://github.com/cilium/cilium/blob/master/test/Vagrantfile>`__
and `root Vagrantfile <https://github.com/cilium/cilium/blob/master/Vagrantfile>`__ after new box is built and tested.

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
* 1.14
* 1.15

By default, the Vagrant VMs are provisioned with Kubernetes 1.13. To run with any other
supported version of Kubernetes, run the test suite with the following format:

::

    K8S_VERSION=<version> ginkgo --focus="K8s*" -noColor

.. note::

   When provisioning VMs with the net-next kernel (``NETNEXT=true``) on
   VirtualBox which version does not match a version of the VM image
   VirtualBox Guest Additions, Vagrant will install a new version of
   the Additions with ``mount.vboxsf``. The latter is not compatible with
   ``vboxsf.ko`` shipped within the VM image, and thus syncing of shared
   folders will not work.

   To avoid this, one can prevent Vagrant from installing the Additions by
   putting the following into ``$HOME/.vagrant.d/Vagrantfile``:

   .. code:: ruby

      Vagrant.configure('2') do |config|
	if Vagrant.has_plugin?("vagrant-vbguest") then
	  config.vbguest.auto_update = false
	end

	config.vm.provider :virtualbox do |vbox|
	  vbox.check_guest_additions = false
	end
      end

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
      -cilium.image string
        	Specifies which image of cilium to use during tests
      -cilium.operator-image string
        	Specifies which image of cilium-operator to use during tests
      -cilium.provision
        	Provision Vagrant boxes and Cilium before running test (default true)
      -cilium.provision-k8s
        	Specifies whether Kubernetes should be deployed and installed via kubeadm or not (default true)
      -cilium.showCommands
        	Output which commands are ran to stdout
      -cilium.skipLogs
        	skip gathering logs if a test fails
      -cilium.testScope string
        	Specifies scope of test to be ran (k8s, Nightly, runtime)   
    

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
and their output in the report directory (``./test/test_results``). Each test
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
| K8S\_VERSION         | 1.13              | 1.\*\*       | Kubernetes version to install                                    |
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


Building Container Images
-------------------------

Two make targets exists to build container images automatically based on the
locally checked out branch:

Developer images
~~~~~~~~~~~~~~~~

::

    DOCKER_IMAGE_TAG=jane-developer-my-fix make dev-docker-image

You can then push the image tag to the registry for development builds:

::

    docker push cilium/cilium-dev:jane-developer-my-fix

Access to the developer builds registry is restricted but access is granted
liberally. Join the #development channel in Slack and ask for permission to
push builds.

Official release images
~~~~~~~~~~~~~~~~~~~~~~~

Anyone can build official release images using the make target below but
pushing to the official registries is restricted to Cilium maintainers. Ask in
the #launchpad Slack channels for the exact details.

::

    DOCKER_IMAGE_TAG=v1.4.0 make docker-image

You can then push the image tag to the registry:

::

    docker push cilium/cilium:v1.4.0

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

Now the documentation page should be browsable on http://localhost:9080.

Update cilium-builder and cilium-runtime images
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Login to quay.io with your credentials to the repository that you want to
update:

`cilium-builder <https://quay.io/repository/cilium/cilium-builder?tab=builds>`__ - contains Cilium build-time dependencies
`cilium-runtime <https://quay.io/repository/cilium/cilium-runtime?tab=builds>`__ - contains Cilium run-time dependencies

0. After login, select the tab "builds" on the left menu.

.. image:: ../images/cilium-quayio-tag-0.png
    :align: center

1. Click on the wheel.
2. Enable the trigger for that build trigger.

.. image:: ../images/cilium-quayio-tag-1.png
    :align: center

3. Confirm that you want to enable the trigger.

.. image:: ../images/cilium-quayio-tag-2.png
    :align: center

4. After enabling the trigger, click again on the wheel.
5. And click on "Run Trigger Now".

.. image:: ../images/cilium-quayio-tag-3.png
    :align: center

6. A new pop-up will appear and you can select the branch that contains your
   changes.
7. Select the branch that contains the new changes.

.. image:: ../images/cilium-quayio-tag-4.png
    :align: center

8. After selecting your branch click on "Start Build".

.. image:: ../images/cilium-quayio-tag-5.png
    :align: center

9. Once the build has started you can disable the Build trigger by clicking on
   the wheel.
10. And click on "Disable Trigger".

.. image:: ../images/cilium-quayio-tag-6.png
    :align: center

11. Confirm that you want to disable the build trigger.

.. image:: ../images/cilium-quayio-tag-7.png
    :align: center

12. Once the build is finished click under Tags (on the left menu).
13. Click on the wheel and;
14. Add a new tag to the image that was built.

.. image:: ../images/cilium-quayio-tag-8.png
    :align: center

15. Write the name of the tag that you want to give for the newly built image.
16. Confirm the name is correct and click on "Create Tag".

.. image:: ../images/cilium-quayio-tag-9.png
    :align: center

17. After the new tag was created you can delete the other tag, which is the
    name of your branch. Select the tag name.
18. Click in Actions.
19. Click in "Delete Tags".

.. image:: ../images/cilium-quayio-tag-10.png
    :align: center

20. Confirm that you want to delete tag with your branch name.

.. image:: ../images/cilium-quayio-tag-11.png
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

   ../commit-access

.. _cilium/nightly: https://hub.docker.com/r/cilium/nightly/
.. _Cilium-Nightly-Tests Job: https://jenkins.cilium.io/job/Cilium-Master-Nightly-Tests-All/

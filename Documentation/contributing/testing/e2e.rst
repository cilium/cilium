.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _testsuite:

End-To-End Testing Framework
============================

Introduction
~~~~~~~~~~~~

Cilium uses `Ginkgo`_ as a testing framework for
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
run the tests. The tests make heavy use of the Ginkgo `focus`_ concept to
determine which VMs are necessary to run particular tests. All test names
*must* begin with one of the following prefixes:

* ``Runtime``: Test cilium in a runtime environment running on a single node.
* ``K8s``: Create a small multi-node kubernetes environment for testing
  features beyond a single host, and for testing kubernetes-specific features.

.. _Ginkgo: https://onsi.github.io/ginkgo/
.. _focus: `Focused Specs`_

Running End-To-End Tests
~~~~~~~~~~~~~~~~~~~~~~~~

Running All Ginkgo Tests
^^^^^^^^^^^^^^^^^^^^^^^^

Running all of the Ginkgo tests may take an hour or longer. To run all the
ginkgo tests, invoke the make command as follows from the root of the cilium
repository:

.. code-block:: shell-session

    $ sudo make -C test/ test

The first time that this is invoked, the testsuite will pull the
`testing VMs <https://app.vagrantup.com/cilium/boxes/ginkgo>`_ and provision
Cilium into them. This may take several minutes, depending on your internet
connection speed. Subsequent runs of the test will reuse the image.

Running Runtime Tests
^^^^^^^^^^^^^^^^^^^^^

To run all of the runtime tests, execute the following command from the ``test`` directory:

.. code-block:: shell-session

    INTEGRATION_TESTS=true ginkgo --focus="Runtime"

Ginkgo searches for all tests in all subdirectories that are "named" beginning
with the string "Runtime" and contain any characters after it. For instance,
here is an example showing what tests will be ran using Ginkgo's dryRun option:

.. code-block:: shell-session

    $ INTEGRATION_TESTS=true ginkgo --focus="Runtime" -dryRun
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

.. _running_k8s_tests:

Running Kubernetes Tests
^^^^^^^^^^^^^^^^^^^^^^^^

To run all of the Kubernetes tests, run the following command from the ``test`` directory:

.. code-block:: shell-session

    INTEGRATION_TESTS=true ginkgo --focus="K8s"

To run a specific test from the Kubernetes tests suite, run the following command
from the ``test`` directory:

.. code-block:: shell-session

    INTEGRATION_TESTS=true ginkgo --focus="K8s.*Check iptables masquerading with random-fully"

Similar to the Runtime test suite, Ginkgo searches for all tests in all
subdirectories that are "named" beginning with the string "K8s" and
contain any characters after it.

The Kubernetes tests support the following Kubernetes versions:

* 1.16
* 1.17
* 1.18
* 1.19
* 1.20
* 1.21
* 1.22
* 1.23
* 1.24
* 1.25
* 1.26

By default, the Vagrant VMs are provisioned with Kubernetes 1.23. To run with any other
supported version of Kubernetes, run the test suite with the following format:

.. code-block:: shell-session

    INTEGRATION_TESTS=true K8S_VERSION=<version> ginkgo --focus="K8s"

.. note::

   When provisioning VMs with the net-next kernel (``NETNEXT=1``) on
   VirtualBox which version does not match a version of the VM image
   VirtualBox Guest Additions, Vagrant will install a new version of
   the Additions with ``mount.vboxsf``. The latter is not compatible with
   ``vboxsf.ko`` shipped within the VM image, and thus syncing of shared
   folders will not work.

   To avoid this, one can prevent Vagrant from installing the Additions by
   putting the following into ``$HOME/.vagrant.d/Vagrantfile``:

   .. code-block:: ruby

      Vagrant.configure('2') do |config|
        if Vagrant.has_plugin?("vagrant-vbguest") then
          config.vbguest.auto_update = false
        end

        config.vm.provider :virtualbox do |vbox|
          vbox.check_guest_additions = false
        end
      end

Available CLI Options
^^^^^^^^^^^^^^^^^^^^^

For more advanced workflows, check the list of available custom options for the Cilium
framework in the ``test/`` directory and interact with ginkgo directly:

.. code-block:: shell-session

    $ cd test/
    $ ginkgo . -- -cilium.help
      -cilium.SSHConfig string
            Specify a custom command to fetch SSH configuration (eg: 'vagrant ssh-config')
      -cilium.help
            Display this help message.
      -cilium.holdEnvironment
            On failure, hold the environment in its current state
      -cilium.hubble-relay-image string
            Specifies which image of hubble-relay to use during tests
      -cilium.hubble-relay-tag string
            Specifies which tag of hubble-relay to use during tests
      -cilium.image string
            Specifies which image of cilium to use during tests
      -cilium.kubeconfig string
            Kubeconfig to be used for k8s tests
      -cilium.multinode
            Enable tests across multiple nodes. If disabled, such tests may silently pass (default true)
      -cilium.operator-image string
            Specifies which image of cilium-operator to use during tests
      -cilium.operator-tag string
            Specifies which tag of cilium-operator to use during tests
      -cilium.passCLIEnvironment
            Pass the environment invoking ginkgo, including PATH, to subcommands
      -cilium.provision
            Provision Vagrant boxes and Cilium before running test (default true)
      -cilium.provision-k8s
            Specifies whether Kubernetes should be deployed and installed via kubeadm or not (default true)
      -cilium.runQuarantined
            Run tests that are under quarantine.
      -cilium.showCommands
            Output which commands are ran to stdout
      -cilium.skipLogs
            skip gathering logs if a test fails
      -cilium.tag string
            Specifies which tag of cilium to use during tests
      -cilium.testScope string
            Specifies scope of test to be ran (k8s, runtime)
      -cilium.timeout duration
            Specifies timeout for test run (default 24h0m0s)

    Ginkgo ran 1 suite in 4.312100241s
    Test Suite Failed

For more information about other built-in options to Ginkgo, consult the
`Ginkgo documentation`_.

.. _Ginkgo documentation: Ginkgo_

Running Specific Tests Within a Test Suite
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you want to run one specified test, there are a few options:

* By modifying code: add the prefix "FIt" on the test you want to run; this
  marks the test as focused. Ginkgo will skip other tests and will only run the
  "focused" test. For more information, consult the `Focused Specs`_
  documentation from Ginkgo.

  .. code-block:: go

      It("Example test", func(){
          Expect(true).Should(BeTrue())
      })

      FIt("Example focused test", func(){
          Expect(true).Should(BeTrue())
      })


* From the command line: specify a more granular focus if you want to focus on, say, Runtime L7 tests:

  .. code-block:: shell-session

      INTEGRATION_TESTS=true ginkgo --focus "Runtime.*L7"


This will focus on tests that contain "Runtime", followed by any
number of any characters, followed by "L7". ``--focus`` is a regular
expression and quotes are required if it contains spaces and to escape
shell expansion of ``*``.

.. _Focused Specs: https://onsi.github.io/ginkgo/#focused-specs

Compiling the tests without running them
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To validate that the Go code you've written for testing is correct without
needing to run the full test, you can build the test directory:

.. code-block:: shell-session

    make -C test/ build

Updating Cilium images for Kubernetes tests
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sometimes when running the CI suite for a feature under development, it's common
to re-run the CI suite on the CI VMs running on a local development machine after
applying some changes to Cilium. For this the new Cilium images have to be
built, and then used by the CI suite. To do so, one can run the following
commands on the ``k8s1`` VM:

.. code-block:: shell-session

   cd go/src/github.com/cilium/cilium

   make LOCKDEBUG=1 docker-cilium-image
   docker tag quay.io/cilium/cilium:latest \
	k8s1:5000/cilium/cilium-dev:latest
   docker push k8s1:5000/cilium/cilium-dev:latest

   make -B LOCKDEBUG=1 docker-operator-generic-image
   docker tag quay.io/cilium/operator-generic:latest \
	k8s1:5000/cilium/operator-generic:latest
   docker push k8s1:5000/cilium/operator-generic:latest

The commands were adapted from the ``test/provision/compile.sh`` script.

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

.. code-block:: go

	AfterFailed(func() {
		vm.ReportFailed()
	})


Ginkgo Extensions
~~~~~~~~~~~~~~~~~

In Cilium, some Ginkgo features are extended to cover some uses cases that are
useful for testing Cilium.

BeforeAll
^^^^^^^^^

This function will run before all `BeforeEach`_ within a `Describe or Context`_.
This method is an equivalent to ``SetUp`` or initialize functions in common
unit test frameworks.

.. _BeforeEach: https://onsi.github.io/ginkgo/#extracting-common-setup-beforeeach
.. _Describe or Context: https://onsi.github.io/ginkgo/#organizing-specs-with-containers-describe-and-context

AfterAll
^^^^^^^^

This method will run after all `AfterEach`_ functions defined in a `Describe or Context`_.
This method is used for tearing down objects created which are used by all
``Its`` within the given ``Context`` or ``Describe``. It is ran after all Its
have ran, this method is a equivalent to ``tearDown`` or ``finalize`` methods in
common unit test frameworks.

A good use case for using ``AfterAll`` method is to remove containers or pods
that are needed for multiple ``Its`` in the given ``Context`` or ``Describe``.

.. _AfterEach: BeforeEach_

JustAfterEach
^^^^^^^^^^^^^

This method will run just after each test and before ``AfterFailed`` and
``AfterEach``. The main reason of this method is to perform some assertions
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

Test description diagram::

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


Test execution flow::

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

You can retrieve all run commands and their output in the report directory
(``./test/test_results``). Each test creates a new folder, which contains
a file called log where all information is saved, in case of a failing
test an exhaustive data will be added.

.. code-block:: shell-session

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

.. code-block:: shell-session

	dlv test . -- --ginkgo.focus="Runtime" -ginkgo.v=true --cilium.provision=false

Running End-To-End Tests In Other Environments via kubeconfig
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The end-to-end tests can be run with an arbitrary kubeconfig file. Normally the
CI will use the kubernetes created via vagrant but this can be overridden with
``--cilium.kubeconfig``. When used, ginkgo will not start a VM nor compile
cilium. It will also skip some setup tasks like labeling nodes for testing.

This mode expects:

- The current directory is ``cilium/test``

- A test focus with ``--focus``. ``--focus="K8s"`` selects all kubernetes tests.
  If not passing ``--focus=K8s`` then you must pass ``-cilium.testScope=K8s``.

- Cilium images as full URLs specified with the ``--cilium.image`` and
  ``--cilium.operator-image`` options.

- A working kubeconfig with the ``--cilium.kubeconfig`` option

- A populated K8S_VERSION environment variable set to the version of the cluster

- If appropriate, set the ``CNI_INTEGRATION`` environment variable set to one
  of ``gke``, ``eks``, ``eks-chaining``, ``microk8s`` or ``minikube``. This selects
  matching configuration overrides for cilium.
  Leaving this unset for non-matching integrations is also correct.

  For k8s environments that invoke an authentication agent, such as EKS and
  ``aws-iam-authenticator``, set ``--cilium.passCLIEnvironment=true``

An example invocation is

.. code-block:: shell-session

  INTEGRATION_TESTS=true CNI_INTEGRATION=eks K8S_VERSION=1.16 ginkgo --focus="K8s" -- -cilium.provision=false -cilium.kubeconfig=`echo ~/.kube/config` -cilium.image="quay.io/cilium/cilium-ci" -cilium.operator-image="quay.io/cilium/operator" -cilium.operator-suffix="-ci" -cilium.passCLIEnvironment=true


To run tests with Kind, try

.. code-block:: shell-session

  K8S_VERSION=1.25 ginkgo --focus=K8s -- -cilium.provision=false --cilium.image=localhost:5000/cilium/cilium-dev -cilium.tag=local  --cilium.operator-image=localhost:5000/cilium/operator -cilium.operator-tag=local -cilium.kubeconfig=`echo ~/.kube/config` -cilium.provision-k8s=false  -cilium.testScope=K8s -cilium.operator-suffix=


Running in GKE
^^^^^^^^^^^^^^

1- Setup a cluster as in :ref:`k8s_install_quick` or utilize an existing
cluster.

.. note:: You do not need to deploy Cilium in this step, as the End-To-End
          Testing Framework handles the deployment of Cilium.

.. note:: The tests require machines larger than ``n1-standard-4``. This can be
          set with ``--machine-type n1-standard-4`` on cluster creation.


2- Invoke the tests from ``cilium/test`` with options set as explained in
`Running End-To-End Tests In Other Environments via kubeconfig`_

.. note:: The tests require the ``NATIVE_CIDR`` environment variable to be set to
          the value of the cluster IPv4 CIDR returned by the ``gcloud container
          clusters describe`` command.

.. code-block:: shell-session

  export CLUSTER_NAME=cluster1
  export CLUSTER_ZONE=us-west2-a
  export NATIVE_CIDR="$(gcloud container clusters describe $CLUSTER_NAME --zone $CLUSTER_ZONE --format 'value(clusterIpv4Cidr)')"

  INTEGRATION_TESTS=true CNI_INTEGRATION=gke K8S_VERSION=1.17 ginkgo --focus="K8sDemo" -- -cilium.provision=false -cilium.kubeconfig=`echo ~/.kube/config` -cilium.image="quay.io/cilium/cilium-ci" -cilium.operator-image="quay.io/cilium/operator" -cilium.operator-suffix="-ci" -cilium.hubble-relay-image="quay.io/cilium/hubble-relay-ci" -cilium.passCLIEnvironment=true

.. note:: The kubernetes version defaults to 1.23 but can be configured with
          versions between 1.16 and 1.23. Version should match the server
          version reported by ``kubectl version``.

AKS (experimental)
^^^^^^^^^^^^^^^^^^

.. note:: The tests require the ``NATIVE_CIDR`` environment variable to be set to
          the value of the cluster IPv4 CIDR.

1. Setup a cluster as in :ref:`k8s_install_quick` or utilize an existing
   cluster. You do not need to deploy Cilium in this step, as the End-To-End
   Testing Framework handles the deployment of Cilium.

2. Invoke the tests from ``cilium/test`` with options set as explained in
`Running End-To-End Tests In Other Environments via kubeconfig`_

.. code-block:: shell-session

    export NATIVE_CIDR="10.241.0.0/16"
    INTEGRATION_TESTS=true CNI_INTEGRATION=aks K8S_VERSION=1.17 ginkgo --focus="K8s" -- -cilium.provision=false -cilium.kubeconfig=`echo ~/.kube/config` -cilium.passCLIEnvironment=true -cilium.image="mcr.microsoft.com/oss/cilium/cilium" -cilium.tag="1.12.1" -cilium.operator-image="mcr.microsoft.com/oss/cilium/operator" -cilium.operator-suffix=""  -cilium.operator-tag="1.12.1"

AWS EKS (experimental)
^^^^^^^^^^^^^^^^^^^^^^

Not all tests can succeed on EKS. Many do, however and may be useful.
:gh-issue:`9678#issuecomment-749350425` contains a list of tests that are still
failing.

1. Setup a cluster as in :ref:`k8s_install_quick` or utilize an existing
   cluster.

2. Source the testing integration script from ``cilium/contrib/testing/integrations.sh``.

3. Invoke the ``gks`` function by passing which ``cilium`` docker image to run
   and the test focus. The command also accepts additional ginkgo arguments.

.. code-block:: shell-session

    gks quay.io/cilium/cilium:latest K8sDemo


Adding new Managed Kubernetes providers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All Managed Kubernetes test support relies on using a pre-configured kubeconfig
file.  This isn't always adequate, however, and adding defaults specific to
each provider is possible. The `commit adding GKE <https://github.com/cilium/cilium/commit/c2d8445fd725c515a635c8c3ad3be901a08084eb>`_
support is a good reference.

1. Add a map of helm settings to act as an override for this provider in
   `test/helpers/kubectl.go <https://github.com/cilium/cilium/blob/26dec4c4f4311df2b1a6c909b27ff7fe6e46929f/test/helpers/kubectl.go#L80-L102>`_.
   These should be the helm settings used when generating cilium specs for this
   provider.

2. Add a unique `CI Integration constant <https://github.com/cilium/cilium/blob/26dec4c4f4311df2b1a6c909b27ff7fe6e46929f/test/helpers/kubectl.go#L66-L67>`_.
   This value is passed in when invoking ginkgo via the ``CNI_INTEGRATON``
   environment variable.

3. Update the `helm overrides <https://github.com/cilium/cilium/blob/26dec4c4f4311df2b1a6c909b27ff7fe6e46929f/test/helpers/kubectl.go#L138-L147>`_
   mapping with the constant and the helm settings.

4. For cases where a test should be skipped use the ``SkipIfIntegration``. To
   skip whole contexts, use ``SkipContextIf``. More complex logic can be
   expressed with functions like ``IsIntegration``. These functions are all
   part of the `test/helpers <https://github.com/cilium/cilium/tree/26dec4c4f4311df2b1a6c909b27ff7fe6e46929f/test/helpers>`_
   package.

Running End-To-End Tests In Other Environments via SSH
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to run tests in an arbitrary environment with SSH access, you can
use ``--cilium.SSHConfig`` to provide the SSH configuration of the endpoint on
which tests will be run. The tests presume the following on the remote
instance:

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

.. code-block:: shell-session

    ginkgo -- --cilium.provision=false --cilium.SSHConfig="cat ssh-config"


VMs for Testing
~~~~~~~~~~~~~~~

The VMs used for testing are defined in ``test/Vagrantfile``. There are a variety of
configuration options that can be passed as environment variables:

+----------------------+-------------------+--------------+------------------------------------------------------------------+
| ENV variable         | Default Value     | Options      | Description                                                      |
+======================+===================+==============+==================================================================+
| K8S\_NODES           | 2                 | 0..100       | Number of Kubernetes nodes in the cluster                        |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| NO_CILIUM_ON_NODE[S] | none              | \*           | Comma-separated list of K8s nodes that should not run Cilium     |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| NFS                  | 0                 | 1            | If Cilium folder needs to be shared using NFS                    |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| IPv6                 | 0                 | 0-1          | If 1 the Kubernetes cluster will use IPv6                        |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| CONTAINER\_RUNTIME   | docker            | containerd   | To set the default container runtime in the Kubernetes cluster   |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| K8S\_VERSION         | 1.18              | 1.\*\*       | Kubernetes version to install                                    |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| KUBEPROXY            | 1                 | 0-1          | If 0 the Kubernetes' kube-proxy won't be installed               |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| SERVER\_BOX          | cilium/ubuntu-dev | \*           | Vagrantcloud base image                                          |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| VM\_CPUS             | 2                 | 0..100       | Number of CPUs that need to have the VM                          |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| VM\_MEMORY           | 4096              | \d+          | RAM size in Megabytes                                            |
+----------------------+-------------------+--------------+------------------------------------------------------------------+

VM images
~~~~~~~~~

The test suite relies on Vagrant to automatically download the required VM
image, if it is not already available on the system. VM images weight several
gigabytes so this may take some time, but faster tools such as `aria2`_ can
speed up the process by opening multiple connections. The script
`contrib/scripts/add_vagrant_box.sh`_ can be useful to manually download
selected images with aria2 prior to launching the test suite, or to
periodically update images in a ``cron`` job::

    $ bash contrib/scripts/add_vagrant_box.sh -h
    usage: add_vagrant_box.sh [options] [vagrant_box_defaults.rb path]
            path to vagrant_box_defaults.rb defaults to ./vagrant_box_defaults.rb

    options:
            -a              use aria2c instead of curl
            -b <box>        download selected box (defaults: ubuntu ubuntu-next)
            -d <dir>        download to dir instead of /tmp/
            -l              download latest versions instead of using vagrant_box_defaults
            -h              display this help

    examples:
            download boxes ubuntu and ubuntu-next from vagrant_box_defaults.rb:
            $ add-vagrant-boxes.sh $HOME/go/src/github.com/cilium/cilium/vagrant_box_defaults.rb
            download latest version for ubuntu-dev and ubuntu-next:
            $ add-vagrant-boxes.sh -l -b ubuntu-dev -b ubuntu-next
            same as above, downloading into /tmp/foo and using aria2c:
            $ add-vagrant-boxes.sh -al -d /tmp/foo -b ubuntu-dev -b ubuntu-next

.. _aria2: https://aria2.github.io/
.. _contrib/scripts/add_vagrant_box.sh:
   https://github.com/cilium/cilium/blob/main/contrib/scripts/add_vagrant_box.sh

Known Issues and Workarounds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

VirtualBox hostonlyifs and DHCP related errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you see the following error, take a look at this `GitHub issue
<https://github.com/hashicorp/vagrant/issues/3083#issuecomment-41156076>`_ for
workarounds.

::

    A host only network interface you're attempting to configure via DHCP
    already has a conflicting host only adapter with DHCP enabled. The
    DHCP on this adapter is incompatible with the DHCP settings. Two
    host only network interfaces are not allowed to overlap, and each
    host only network interface can have only one DHCP server. Please
    reconfigure your host only network or remove the virtual machine
    using the other host only network.

Also, consider upgrading VirtualBox and Vagrant to the latest versions.

Further Assistance
~~~~~~~~~~~~~~~~~~

Have a question about how the tests work or want to chat more about improving the
testing infrastructure for Cilium? Hop on over to the
`testing <https://cilium.slack.com/messages/C7PE7V806>`_ channel on Slack.

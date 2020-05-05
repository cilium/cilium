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
* ``Nightly``: sets up a multinode Kubernetes cluster to run scale, performance, and chaos testing for Cilium.

.. _Ginkgo: https://onsi.github.io/ginkgo/
.. _focus: `Focused Specs`_

Running End-To-End Tests
~~~~~~~~~~~~~~~~~~~~~~~~

Running All Ginkgo Tests
^^^^^^^^^^^^^^^^^^^^^^^^

Running all of the Ginkgo tests may take an hour or longer. To run all the
ginkgo tests, invoke the make command as follows from the root of the cilium
repository:

::

    $ sudo make -C test/ test

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
* 1.16
* 1.17
* 1.18

By default, the Vagrant VMs are provisioned with Kubernetes 1.13. To run with any other
supported version of Kubernetes, run the test suite with the following format:

::

    K8S_VERSION=<version> ginkgo --focus="K8s*" -noColor

.. note::

   When provisioning VMs with the net-next kernel (``NETNEXT=1``) on
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
`Ginkgo documentation`_.

.. _Ginkgo documentation: Ginkgo_

Running Specific Tests Within a Test Suite
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you want to run one specified test, there are a few options:

* By modifying code: add the prefix "FIt" on the test you want to run; this
  marks the test as focused. Ginkgo will skip other tests and will only run the
  "focused" test. For more information, consult the `Focused Specs`_
  documentation from Ginkgo.

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

.. _Focused Specs: https://onsi.github.io/ginkgo/#focused-specs

Compiling the tests without running them
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To validate that the Go code you've written for testing is correct without
needing to run the full test, you can build the test directory:

::

	make -C test/ build

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

Running End-To-End Tests In Other Environments via kubeconfig
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The end-to-end tests can be run with an arbitrary kubeconfig file. Normally the
CI will use the kubernetes created via vagrant but this can be overridden with
``--cilium.kubeconfig``. When used, ginkgo will not start a VM nor compile
cilium. It will also skip some setup tasks like labeling nodes for testing.

This mode expects:

- The current directory is ``cilium/test``

- A test focus with ``--focus``. ``--focus="K8s*"`` selects all kubernetes tests.

- Cilium images as full URLs specified with the ``--cilium.image`` and
  ``--cilium.operator-image`` options, with matching ``CILIUM_IMAGE`` and
  ``CILIUM_OPERATOR_IMAGE`` environment variables.

- A working kubeconfig with the ``--cilium.kubeconfig`` option

- A populated K8S_VERSION environment variable set to the version of the cluster

- If appropriate, set the ``CNI_INTEGRATION`` environment variable set to one
  of ``flannel``, ``gke``, ``eks``, ``microk8s`` or ``minikube``. This selects
  matching configuration overrides for cilium.
  Leaving this unset for non-matching integrations is also correct.

  For k8s environments that invoke an authentication agent, such as EKS and
  ``aws-iam-authenticator``, set ``--cilium.passCLIEnvironment=true``

An example invocation is

::

  CNI_INTEGRATION=eks K8S_VERSION=1.13 CILIUM_IMAGE="quay.io/cilium/cilium:latest" CILIUM_OPERATOR_IMAGE="quay.io/cilium/operator:latest" ginkgo --focus="K8s*" -noColor -- -cilium.provision=false -cilium.kubeconfig=`echo ~/.kube/config` -cilium.image="quay.io/cilium/cilium:latest" -cilium.operator-image="quay.io/cilium/operator:latest" -cilium.passCLIEnvironment=true

GKE (experimental)
^^^^^^^^^^^^^^^^^^^^^^

Not all tests can succeed on GKE. Many do, however and may be useful.

1- Setup a cluster as in :ref:`k8s_install_gke` or utilize an existing
cluster.

.. note:: The tests require machines larger than ``n1-standard-4``. This can be
          set with ``--machine-type n1-standard-4`` on cluster creation.


2- Label 2 nodes for testing with ``cilium.io/ci-node=k8s1`` and
``cilium.io/ci-node=k8s2``

::

  kubectl label node gke-my-cluster-default-pool-b011879a-6j26 cilium.io/ci-node=k8s1
  kubectl label node gke-my-cluster-default-pool-b011879a-b1r2 cilium.io/ci-node=k8s2

3- Invoke the tests from ``cilium/test`` with options set as explained in
`Running End-To-End Tests In Other Environments via kubeconfig`_

::

  CNI_INTEGRATION=gke K8S_VERSION=1.13 CILIUM_IMAGE="quay.io/cilium/cilium:latest" CILIUM_OPERATOR_IMAGE="quay.io/cilium/operator:latest" ginkgo --focus="K8s*" -noColor -- -cilium.provision=false -cilium.kubeconfig=`echo ~/.kube/config` -cilium.image="quay.io/cilium/cilium:latest" -cilium.operator-image="quay.io/cilium/operator:latest" -cilium.passCLIEnvironment=true

.. note:: The kubernetes version defaults to 1.13 but can be configured with
          versions between 1.13 and 1.15. Check with ``kubectl version`` 

AWS EKS (experimental)
^^^^^^^^^^^^^^^^^^^^^^

Not all tests can succeed on EKS. Many do, however and may be useful.

1- Setup a cluster as in :ref:`k8s_install_eks` or utilize an existing
cluster.

2- Label 2 nodes for testing with ``cilium.io/ci-node=k8s1`` and
``cilium.io/ci-node=k8s2``

::

  kubectl label node ip-192-168-6-126.us-west-2.compute.internal cilium.io/ci-node=k8s1
  kubectl label node ip-192-168-68-145.us-west-2.compute.internal cilium.io/ci-node=k8s2

3- Invoke the tests from ``cilium/test`` with options set as explained in
`Running End-To-End Tests In Other Environments via kubeconfig`_

::

  CNI_INTEGRATION=eks K8S_VERSION=1.14 CILIUM_IMAGE="quay.io/cilium/cilium:latest" CILIUM_OPERATOR_IMAGE="quay.io/cilium/operator:latest" ginkgo --focus="K8s*" -noColor -- -cilium.provision=false -cilium.kubeconfig=`echo ~/.kube/config` -cilium.image="quay.io/cilium/cilium:latest" -cilium.operator-image="quay.io/cilium/operator:latest" -cilium.passCLIEnvironment=true

Be sure to pass ``--cilium.passCLIEnvironment=true`` to allow kubectl to invoke ``aws-iam-authenticator``

.. note:: The kubernetes version varies between AWS regions. Be sure to check with ``kubectl version``

Adding new Managed Kubernetes providers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All Managed Kubernetes test support relies on using a pre-configured kubeconfig
file.  This isn't always adequate, however, and adding defaults specific to
each provider is possible. The `commit adding GKE <https://github.com/cilium/cilium/commit/c2d8445fd725c515a635c8c3ad3be901a08084eb>`_
support is a good reference.

1- Add a map of helm settings to act as an override for this provider in
`test/helpers/kubectl.go <https://github.com/cilium/cilium/blob/26dec4c4f4311df2b1a6c909b27ff7fe6e46929f/test/helpers/kubectl.go#L80-L102>`_.
These should be the helm settings used when generating cilium specs for this provider.

2- Add a unique `CI Integration constant <https://github.com/cilium/cilium/blob/26dec4c4f4311df2b1a6c909b27ff7fe6e46929f/test/helpers/kubectl.go#L66-L67>`_.
This value is passed in when invoking ginkgo via the ``CNI_INTEGRATON``
environment variable.

3- Update the `helm overrides <https://github.com/cilium/cilium/blob/26dec4c4f4311df2b1a6c909b27ff7fe6e46929f/test/helpers/kubectl.go#L138-L147>`_
mapping with the constant and the helm settings.

4- For cases where a test should be skipped use the ``SkipIfIntegration``. To
skip whole contexts, use ``SkipContextIf``. More complex logic can be expressed
with functions like ``IsIntegration``. These functions are all part of the
`test/helpers <https://github.com/cilium/cilium/tree/26dec4c4f4311df2b1a6c909b27ff7fe6e46929f/test/helpers>`_
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
| VM\_CPUS             | 2                 | 0..100       | Number of CPUs that need to have the VM                          |
+----------------------+-------------------+--------------+------------------------------------------------------------------+
| VM\_MEMORY           | 4096              | \d+          | RAM size in Megabytes                                            |
+----------------------+-------------------+--------------+------------------------------------------------------------------+

Further Assistance
~~~~~~~~~~~~~~~~~~

Have a question about how the tests work or want to chat more about improving the
testing infrastructure for Cilium? Hop on over to the
`testing <https://cilium.slack.com/messages/C7PE7V806>`_ channel on Slack.

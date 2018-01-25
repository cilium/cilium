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

+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
| Dependency                                                                       | Version / Commit ID   | Download Command                                           |
+==================================================================================+=======================+============================================================+
| git                                                                              | latest                | N/A (OS-specific)                                          |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
| `go <https://golang.org/dl/>`_                                                   | 1.9                   | N/A (OS-specific)                                          |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
| `go-swagger <https://github.com/go-swagger/go-swagger/tree/master/cmd/swagger>`_ | 0.12.0                | ``go get -u github.com/go-swagger/go-swagger/cmd/swagger`` |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
| `go-bindata <https://github.com/jteeuwen/go-bindata>`_                           | ``a0ff2567cfb``       | ``go get -u github.com/jteeuwen/go-bindata/...``           |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
+ `ginkgo <https://github.com/onsi/ginkgo>`_                                       | >= 1.4.0              | ``go get -u github.com/onsi/ginkgo``                       |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
+ `gomega <https://github.com/onsi/gomega>`_                                       | >= 1.2.0              | ``go get -u github.com/onsi/gomega``                       |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
+ `Kubernetes code generator <https://github.com/kubernetes/code-generator>`_      | ``1f9d929a2d3``       | ``go get -u k8s.io/code-generator``                        |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
+ `Docker <https://docs.docker.com/engine/installation/>`_                         | OS-Dependent          | N/A (OS-specific)                                          |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
+ `Docker-Compose <https://docs.docker.com/compose/install/>`_                     | OS-Dependent          | N/A (OS-specific)                                          |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+

To run Cilium locally on VMs, you need:

+----------------------------------------------------------------------------------+-----------------------+--------------------------------------------------------------------------------+
| Dependency                                                                       | Version / Commit ID   | Download Command                                                               |
+==================================================================================+=======================+================================================================================+
| `Vagrant <https://www.vagrantup.com/downloads.html>`_                            | >= 1.8.3              | `Vagrant Install Instructions <https://www.vagrantup.com/docs/installation/>`_ |
+----------------------------------------------------------------------------------+-----------------------+--------------------------------------------------------------------------------+
| `VirtualBox <https://www.virtualbox.org/wiki/Downloads>`_ (if not using libvirt) | >= 5.1.22             | N/A (OS-specific)                                                              |
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
``cilium/ubuntu-16.10``. The box is currently available for the
following providers:

* libvirt
* virtualbox

Options
^^^^^^^

The following environment variables can be set to customize the VMs
brought up by vagrant:

* ``NWORKERS=n``: Number of child nodes you want to start with the master,
  default 0.
* ``RELOAD=1``: Issue a ``vagrant reload`` instead of ``vagrant up``
* ``NFS=1``: Use NFS for vagrant shared directories instead of rsync
* ``K8S=1``: Build & install kubernetes on the nodes
* ``IPV4=1``: Run Cilium with IPv4 enabled
* VAGRANT\_DEFAULT\_PROVIDER={virtualbox \| libvirt \| ...}

If you want to start the VM with cilium enabled with IPv4, with
kubernetes installed and plus a worker, run:

::

	$ IPV4=1 K8S=1 NWORKERS=1 contrib/vagrant/start.sh

If you have any issue with the provided vagrant box
``cilium/ubuntu-16.10`` or need a different box format, you may
build the box yourself using the `packer scripts <https://github.com/cilium/packer-ubuntu-16.10>`_

Manual Installation
^^^^^^^^^^^^^^^^^^^

Alternatively you can import the vagrant box ``cilium/ubuntu-16.10``
directly and manually install Cilium:

::

        $ vagrant init cilium/ubuntu-16.10
        $ vagrant up
        $ vagrant ssh [...]
        $ cd go/src/github.com/cilium/cilium/
        $ make
        $ sudo make install
        $ sudo cp contrib/upstart/* /etc/init/
        $ sudo usermod -a -G cilium vagrant
        $ sudo service cilium restart

Notes
^^^^^

Your Cilium tree is mapped to the VM so that you do not need to keep
copying files between your host and the VM.  The default sync method
is rsync, which only syncs when the VM is brought up, or when manually
triggered (``vagrant rsync`` command in the Cilium tree).  You can
also use NFS to access your Cilium tree from the VM by setting the
environment variable ``NFS`` (mentioned above) before running the startup script
(``export NFS=1``).  Note that your host firewall have the NFS UDP
ports open, the startup script will give the address and port details
for this.

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


Development Cycle (Bash Script Framework)
-----------------------------------------

The Vagrantfile in the Cilium repo root (hereon just ``Vagrantfile``),
always provisions Cilium build and install when the VM is started.
After the initial build and install you can do further building and
testing incrementally inside the VM. ``vagrant ssh`` takes you to the
Cilium source tree directory
(``/home/vagrant/go/src/github.com/cilium/cilium``) by default, and the
following commands assume that being your current directory.

Build
~~~~~

Assuming you have synced (rsync) the source tree after you have made
changes, or the tree is automatically in sync via NFS or guest
additions folder sharing, you can issue a build as follows:

::

    $ make

A successful build should be followed by running the unit tests:

::

    $ make tests

Install
~~~~~~~

After a successful build and test you can re-install Cilium by:

::

    $ sudo -E make install

Restart Cilium service
~~~~~~~~~~~~~~~~~~~~~~

To run the newly installed version of Cilium, restart the service:

::

    $ sudo service cilium restart

You can verify the service and cilium-agent status by the following
commands, respectively:

::

    $ service cilium status
    $ cilium status

.. _testsuite:

Runtime Tests
~~~~~~~~~~~~~

.. Warning::

  Running the testsuite will modify the host environment. If you are using the
  default VM that might not be an issue, but if you are running bare-metal or a
  different VM the tests might fail or worst case remove possibly important
  configuration. Specifically, they are modifying the state and configuration of
  the system including, changes to ``iptables`` configuration, kernel
  configuration via ``sysctl``, adding and removing networking devices, routes,
  etc. via ``iproute2``. Please note this is not meant to be a complete summary,
  but a heads-up if you are planning to run the testsuite somewhere else than in
  the developer VM.

After the new version of Cilium is running, you should run the runtime tests:

::

    $ sudo make runtime-tests

Development Cycle (Ginkgo Framework)
------------------------------------

Introduction
~~~~~~~~~~~~

There is ongoing progress to move over to a more robust testing framework than
a collection of Bash scripts for testing Cilium. `Ginkgo <https://onsi.github.io/ginkgo>`_
has been chosen as this testing framework
The tests in the `test` directory are built on top of Ginkgo. Ginkgo provides
a rich framework for developing tests alongside the benefits of Golang
(compilation-time checks, types, etc.). To get accustomsed to the basics of
Ginkgo, we recommend reading the
`Ginkgo Getting-Started Guide <https://onsi.github.io/ginkgo/#getting-started-writing-your-first-test>`_ ,
as well as running `example tests <https://github.com/onsi/composition-ginkgo-example>`_
to get a feel for the Ginkgo workflow.

These test scripts will invoke ``vagrant`` to create virtual machine(s) to
run the tests. The tests make heavy use of the Ginkgo `focus <https://onsi.github.io/ginkgo/#focused-specs>`_ concept to
determine which VMs are necessary to run particular tests. All test names
*must* begin with one of the following prefixes:

* ``Runtime``: Test cilium in a runtime environment running on a single node.
* ``K8s``: Create a small multi-node kubernetes environment for testing
  features beyond a single host, and for testing kubernetes-specific features.
* ``Nightly``: sets up a multinode Kubernetes cluster to run scale, performance, and chaos testing for Cilium.

Running Tests
~~~~~~~~~~~~~

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

To run all of the runtime tests, execute the following command from the `test` directory:

::

    ginkgo --focus="Runtime*" -noColor

Ginkgo searches for all tests in all subdirectories that are "named" beginning
with the string "Runtime" and contain any characters after it. For instance,
here is an example showing what tests will be ran using Ginkgo's dryRun option:

::

    $ ginkgo --focus="Runtime*" -noColor -dryRun
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

To run all of the Kubernetes tests, run the following command from the `test` directory:

::

    ginkgo --focus="K8s*" -noColor


Similar to the Runtime test suite, Ginkgo searches for all tests in all
subdirectories that are "named" beginning with the string "K8s" and
contain any characters after it.

The Kubernetes tests support the following Kubernetes versions:

* 1.6
* 1.7

By default, the Vagrant VMs are provisioned with Kubernetes 1.7. To run with any other
supported version of Kubernetes, run the test suite with the following format:

::

    K8S_VERSION=<version> ginkgo --focus="K8s*" -noColor

Running Nightly Tests
^^^^^^^^^^^^^^^^^^^^^

To run all of the Nightly tests, run the following command from the `test` directory:

::

    ginkgo --focus="Nightly*"  -noColor

Similar to the other test suites, Ginkgo searches for all tests in all
subdirectories that are "named" beginning with the string "Nightly" and
contain any characters after it.

Nightly Testing Jenkins Setup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Nightly tests run once per day in the `Cilium-Nightly-Tests Job <https://jenkins.cilium.io/job/Cilium-Nightly-Tests/>`_.
The configuration for this job is stored in ``Jenkinsfile.nightly``.

To see the results of these tests, you can view the JUnit Report for an individual job:

1. Click on the build number you wish to get test results from on the left hand side of the `Cilium-Nightly-Tests Job <https://jenkins.cilium.io/job/Cilium-Nightly-Tests/>`_.
2. Click on 'Test Results' on the left side of the page to view the results from the build.
   This will give you a report of which tests passed and failed. You can click on each test
   to view its corresponding output created from Ginkgo.

Available CLI Options
^^^^^^^^^^^^^^^^^^^^^

For more advanced workflows, check the list of available custom options for the Cilium
framework in the ``test/`` directory and interact with ginkgo directly:

::

    $ cd test/
    $ ginkgo -- --help | grep -A 1 cilium
      -cilium.holdEnvironment
            On failure, hold the environment in its current state
      -cilium.provision
            Provision Vagrant boxes and Cilium before running test (default true)
    $ ginkgo --focus "Policies*" -- -cilium.holdEnvironment

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

    FIt("Example focussed test", func(){
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
* Gather logs in the case that a test fails. If a test fails while running on Jenkins, a postmortem needs to be done to analyze why. So, dumping logs to a location where Jenkins can pick them up is of the highest imperative. Use the following code in an `AfterEach <https://onsi.github.io/ginkgo/#extracting-common-setup-beforeeach>`_ for all tests:

::

    if CurrentGinkgoTestDescription().Failed {
        vm.ReportFailed()
    }

Debugging:
~~~~~~~~~~~

Ginkgo provides to us different ways of debugging. In case that you want to see
all the logs messages in the console you can run the test in verbose mode using
the option `-v`:

::

	ginkgo --focus "Runtime*" -v

In case that the verbose mode is not enough, you can retrieve all run commands
and their output in the report directory (`./test/test-results`). Each test
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

Alternatively you can use a Docker container to build the pages.

::

    $ docker run -ti -v $(pwd):/srv/ cilium/docs-builder /bin/bash -c 'make html'

This behave similarly to running the ``make`` command above so the path to the
build is the same.

There is also a separate target for building and starting a web server with
your document changes.

::

    $ make render

Now the documentation page should be browsable on http://localhost:8080

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
    cilium_calls_3978   cilium_calls_netdev_ns_1  cilium_events           cilium_lb6_reverse_nat  cilium_policy        cilium_policy_4314   cilium_policy_reserved_2  tunnel_endpoint_map
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

+-------------------------------------------------------------------------------------+-----------------+--------------------+
| Jenkins Job                                                                         | Trigger Phrase  | Required To Merge? |
+=====================================================================================+=================+====================+
| `Cilium-Bash-Tests <https://jenkins.cilium.io/job/Cilium-Bash-Tests/>`_             | test-me-please  | Yes                |
+-------------------------------------------------------------------------------------+-----------------+--------------------+
| `Cilium-Ginkgo-Tests <https://jenkins.cilium.io/job/Cilium-Ginkgo-Tests/>`_         | test-me-please  | Yes                |
+-------------------------------------------------------------------------------------+-----------------+--------------------+
| `Cilium-Ginkgo-Tests-All <https://jenkins.cilium.io/job/Cilium-Ginkgo-Tests-All/>`_ | test-all-ginkgo | No                 |
+-------------------------------------------------------------------------------------+-----------------+--------------------+
| `Cilium-Nightly-Tests-PR <https://jenkins.cilium.io/job/Cilium-Nightly-Tests-PR/>`_ | test-nightly    | No                 |
+-------------------------------------------------------------------------------------+-----------------+--------------------+


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


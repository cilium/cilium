
.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _dev_env:

Development Setup
=================

This page provides an overview of different methods for efficient
development on Cilium. Depending on your needs, you can choose the most
suitable method.

Quick Start
-----------

If you're in a hurry, here are the essential steps to get started:

On Linux:

1. ``make kind`` - Provisions a Kind cluster.
2. ``make kind-install-cilium-fast`` - Installs Cilium on the Kind cluster.
3. ``make kind-image-fast`` - Builds Cilium and deploys it.

On any OS:

1. ``make kind`` - Provisions a Kind cluster.
2. ``make kind-image`` - Builds Docker images.
3. ``make kind-install-cilium`` - Installs Cilium on the Kind cluster.

Detailed Instructions
---------------------

Depending on your specific development environment and requirements, you
can follow the detailed instructions below.

Verifying Your Development Setup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Assuming you have Go installed, you can quickly verify many elements of your
development setup by running the following command:

.. code-block:: shell-session

    $ make dev-doctor

Depending on your end-goal, not all dependencies listed are required to develop
on Cilium. For example, "Ginkgo" is not required if you want to improve our
documentation. Thus, do not consider that you need to have all tools installed.

Version Requirements
~~~~~~~~~~~~~~~~~~~~

If using these tools, you need to have the following versions from them
in order to effectively contribute to Cilium:

+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
| Dependency                                                        | Version / Commit ID          | Download Command                                                |
+===================================================================+==============================+=================================================================+
|  git                                                              | latest                       | N/A (OS-specific)                                               |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
|  clang                                                            | >= 17.0 (latest recommended) | N/A (OS-specific)                                               |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
|  llvm                                                             | >= 17.0 (latest recommended) | N/A (OS-specific)                                               |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
| `go <https://golang.org/dl/>`_                                    | |GO_RELEASE|                 | N/A (OS-specific)                                               |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
+ `ginkgo <https://github.com/onsi/ginkgo>`__                       | >= 1.4.0 and < 2.0.0         | ``go install github.com/onsi/ginkgo/ginkgo@v1.16.5``            |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
+ `golangci-lint <https://github.com/golangci/golangci-lint>`_      | >= v1.27                     | N/A (OS-specific)                                               |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
+ `Docker <https://docs.docker.com/engine/installation/>`_          | OS-Dependent                 | N/A (OS-specific)                                               |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
+ `Docker-Compose <https://docs.docker.com/compose/install/>`_      | OS-Dependent                 | N/A (OS-specific)                                               |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
+ python3-pip                                                       | latest                       | N/A (OS-specific)                                               |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
+ `helm <https://helm.sh/docs/intro/install/>`_                     | >= v3.13.0                   | N/A (OS-specific)                                               |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
+ `kind <https://kind.sigs.k8s.io/docs/user/quick-start/>`__        | >= v0.7.0                    | ``go install sigs.k8s.io/kind@v0.19.0``                         |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
+ `kubectl <https://kubernetes.io/docs/tasks/tools/#kubectl>`_      | >= v1.26.0                   | N/A (OS-specific)                                               |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+
+ `cilium-cli <https://github.com/cilium/cilium-cli#installation>`_ | Cilium-Dependent             | N/A (OS-specific)                                               |
+-------------------------------------------------------------------+------------------------------+-----------------------------------------------------------------+

For `integration_testing`, you will need to run ``docker`` without privileges.
You can usually achieve this by adding your current user to the ``docker``
group.

Kind-based Setup (preferred)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can find the setup for a `kind <https://kind.sigs.k8s.io/>`_ environment in
``contrib/scripts/kind.sh``. This setup doesn't require any VMs and/or
VirtualBox on Linux, but does require `Docker for Mac
<https://docs.docker.com/desktop/install/mac-install/>`_ for Mac OS.

Makefile targets automate the task of spinning up an environment:

* ``make kind``: Creates a kind cluster based on the configuration passed in.
  For more information, see `configurations_for_clusters`.
* ``make kind-down``: Tears down and deletes the cluster.

Depending on your environment you can build Cilium by using the following
makefile targets:

For Linux and Mac OS
^^^^^^^^^^^^^^^^^^^^

Makefile targets automate building and installing Cilium images:

* ``make kind-image``: Builds all Cilium images and loads them into the
  cluster.
* ``make kind-image-agent``: Builds only the Cilium Agent image and loads it
  into the cluster.
* ``make kind-image-operator``: Builds only the Cilium Operator (generic) image
  and loads it into the cluster.
* ``make kind-debug``: Builds all Cilium images with optimizations disabled and
  ``dlv`` embedded for live debugging enabled and loads the images into the
  cluster.
* ``make kind-debug-agent``: Like ``kind-debug``, but for the agent image only.
  Use if only the agent image needs to be rebuilt for faster iteration.
* ``make kind-install-cilium``: Installs Cilium into the cluster using the
  Cilium CLI.

The preceding list includes the most used commands for **convenience**. For more
targets, see the ``Makefile`` (or simply run ``make help``).

For Linux only - with shorter development workflow time
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

On Linux environments, or on environments where you can compile and run
Cilium, it is possible to use "fast" targets. These fast targets will build
Cilium in the local environment and mount that binary, as well the bpf source
code, in an pre-existing running Cilium container.

* ``make kind-install-cilium-fast``: Installs Cilium into the cluster using the
  Cilium CLI with the volume mounts defined.

* ``make kind-image-fast``: Builds all Cilium binaries and loads them into all
  kind clusters available in the host.

Configuration for Cilium
^^^^^^^^^^^^^^^^^^^^^^^^

The Makefile targets that install Cilium pass the following list of Helm
values (YAML files) to the Cilium CLI.

* ``contrib/testing/kind-common.yaml``: Shared between normal and fast installation modes.
* ``contrib/testing/kind-values.yaml``: Used by normal installation mode.
* ``contrib/testing/kind-fast.yaml``: Used by fast installation mode.
* ``contrib/testing/kind-custom.yaml``: User defined custom values that are applied if
  the file is present. The file is ignored by Git as specified in ``contrib/testing/.gitignore``.

.. _configurations_for_clusters:

Configuration for clusters
^^^^^^^^^^^^^^^^^^^^^^^^^^

``make kind`` takes a few environment variables to modify the configuration of
the clusters it creates. The following parameters are the most commonly used:

* ``CONTROLPLANES``: How many control-plane nodes are created.
* ``WORKERS``: How many worker nodes are created.
* ``CLUSTER_NAME``: The name of the Kubernetes cluster.
* ``IMAGE``: The image for kind, for example: ``kindest/node:v1.11.10``.
* ``KUBEPROXY_MODE``: Pass directly as ``kubeProxyMode`` to the kind
  configuration Custom Resource Definition (CRD).

For more environment variables, see ``contrib/scripts/kind.sh``.

.. _making_changes:

Making Changes
--------------

#. Make sure the ``main`` branch of your fork is up-to-date:

   .. code-block:: shell-session

      git fetch upstream main:main

#. Create a PR branch with a descriptive name, branching from ``main``:

   .. code-block:: shell-session

      git switch -c pr/changes-to-something main

#. Make the changes you want.
#. Separate the changes into logical commits.

   #. Describe the changes in the commit messages. Focus on answering the
      question why the change is required and document anything that might be
      unexpected.
   #. If any description is required to understand your code changes, then
      those instructions should be code comments instead of statements in the
      commit description.

   .. note::

      For submitting PRs, all commits need be to signed off (``git commit -s``). See the section :ref:`dev_coo`.

#. Make sure your changes meet the following criteria:

   #. New code is covered by :ref:`integration_testing`.
   #. End to end integration / runtime tests have been extended or added. If
      not required, mention in the commit message what existing test covers the
      new code.
   #. Follow-up commits are squashed together nicely. Commits should separate
      logical chunks of code and not represent a chronological list of changes.

#. Run ``git diff --check`` to catch obvious white space violations
#. Run ``make`` to build your changes. This will also run ``make lint`` and error out
   on any golang linting errors. The rules are configured in ``.golangci.yaml``
#. Run ``make -C bpf checkpatch`` to validate against your changes
   coding style and commit messages.
#. See :ref:`integration_testing` on how to run integration tests.
#. See :ref:`testsuite` for information how to run the end to end integration
   tests
#. If you are making documentation changes, you can generate documentation files
   and serve them locally on ``http://localhost:9081`` by running ``make render-docs``.
   This make target works assuming that ``docker`` is running in the environment.

Dev Container
-------------

Cilium provides `Dev Container <https://code.visualstudio.com/docs/devcontainers/containers>`_ configuration for Visual Studio Code Remote Containers
and `Github Codespaces <https://docs.github.com/en/codespaces/setting-up-your-project-for-codespaces/introduction-to-dev-containers>`_.
This allows you to use a preconfigured development environment in the cloud or locally.
The container is based on the official Cilium builder image and provides all the dependencies
required to build Cilium.

You can also install common packages, such as kind, kubectl, and cilium-cli, with ``contrib/scripts/devcontainer-setup.sh``:

.. code-block:: shell-session

    $ ./contrib/scripts/devcontainer-setup.sh

Package versions can be modified to fit your requirements.
This needs to only be set up once when the ``devcontainer`` is first created.

.. note::

    The current Dev Container is running as root. Non-root user support requires non-root
    user in Cilium builder image, which is related to :gh-issue:`23217`.

Update a golang version
-----------------------

Minor version
~~~~~~~~~~~~~

Each Cilium release is tied to a specific version of Golang via an explicit constraint
in our Renovate configuration.

We aim to build and release all maintained Cilium branches using a Golang version
that is actively supported. This needs to be balanced against the desire to avoid
regressions in Golang that may impact Cilium. Golang supports two minor versions
at any given time – when updating the version used by a Cilium branch, you should
choose the older of the two supported versions.

To update the minor version of Golang used by a release, you will first need to
update the Renovate configuration found in ``.github/renovate.json5``. For each
minor release, there will be a section that looks like this:

.. code-block:: json

    {
      "matchPackageNames": [
        "docker.io/library/golang",
        "go"
      ],
      "allowedVersions": "<1.21",
      "matchBaseBranches": [
        "v1.14"
      ]
    }

To allow Renovate to create a pull request that updates the minor Golang version,
bump the ``allowedVersions`` constraint to include the desired minor version. Once
this change has been merged, Renovate will create a pull request that updates the
Golang version. Minor version updates may require further changes to ensure that
all Cilium features are working correctly – use the CI to identify any issues that
require further changes, and bring them to the attention of the Cilium maintainers
in the pull request.

Once the CI is passing, the PR will be merged as part of the standard version
upgrade process.

Patch version
~~~~~~~~~~~~~

New patch versions of Golang are picked up automatically by the CI; there should
normally be no need to update the version manually.

Add/update a golang dependency
------------------------------

Let's assume we want to add ``github.com/containernetworking/cni`` version ``v0.5.2``:

.. code-block:: shell-session

    $ go get github.com/containernetworking/cni@v0.5.2
    $ go mod tidy
    $ go mod vendor
    $ git add go.mod go.sum vendor/

For a first run, it can take a while as it will download all dependencies to
your local cache but the remaining runs will be faster.

Updating k8s is a special case which requires updating k8s libraries in a single
change:

.. code-block:: shell-session

    $ # get the tag we are updating (for example ``v0.17.3`` corresponds to k8s ``v1.17.3``)
    $ # open go.mod and search and replace all ``v0.17.3`` with the version
    $ # that we are trying to upgrade with, for example: ``v0.17.4``.
    $ # Close the file and run:
    $ go mod tidy
    $ go mod vendor
    $ make generate-k8s-api
    $ git add go.mod go.sum vendor/

Add/update a cilium/kindest-node image
--------------------------------------

Cilium might use its own fork of kindest-node so that it can use k8s versions
that have not been released by Kind maintainers yet.

One other reason for using a fork is that the base image used on kindest-node
may not have been release yet. For example, as of this writing, Cilium requires
Debian Bookworm (yet to be released), because the glibc version available on
Cilium's base Docker image is the same as the one used in the Bookworm Docker
image which is relevant for testing with Go's race detector.

Currently, only maintainers can publish an image on ``quay.io/cilium/kindest-node``.
However, anyone can build a kindest-node image and try it out

To build a cilium/kindest-node image, first build the base Docker image:

   .. code-block:: shell-session

    git clone https://github.com/kubernetes-sigs/kind.git
    cd kind
    make -C images/base/ quick

Take note of the resulting image tag for that command, it should be the last
tag built for the ``gcr.io/k8s-staging-kind/base`` repository in ``docker ps -a``.

Secondly, change into the directory with Kubernetes' source code which will be
used for the kindest node image. On this example, we will build a kindest-base
image with Kubernetes version ``v1.28.3`` using the recently-built base image
``gcr.io/k8s-staging-kind/base:v20231108-a9fbf702``:

   .. code-block:: shell-session

    $ # Change to k8s' source code directory.
    $ git clone https://github.com/kubernetes/kubernetes.git
    $ cd kubernetes
    $ tag=v1.28.3
    $ git fetch origin --tags
    $ git checkout tags/${tag}
    $ kind build node-image \
      --image=quay.io/cilium/kindest-node:${tag} \
      --base-image=gcr.io/k8s-staging-kind/base:v20231108-a9fbf702

Finally, publish the image to a public repository. If you are a maintainer and
have permissions to publish on ``quay.io/cilium/kindest-node``, the Renovate bot
will automatically pick the new version and create a new Pull Request with this
update. If you are not a maintainer you will have to update the image manually
in Cilium's repository.

Add/update a new Kubernetes version
-----------------------------------

Let's assume we want to add a new Kubernetes version ``v1.19.0``:

#. Follow the above instructions to update the Kubernetes libraries.

#. Follow the next instructions depending on if it is a minor update or a patch
   update.

Minor version
~~~~~~~~~~~~~

#. Check if it is possible to remove the last supported Kubernetes version from
   :ref:`k8scompatibility`, :ref:`k8s_requirements`, :ref:`test_matrix`,
   :ref:`running_k8s_tests`, :ref:`gsg_istio` and add the new Kubernetes
   version to that list.

#. If the minimal supported version changed, leave a note in the upgrade guide
   stating the minimal supported Kubernetes version.

#. If the minimal supported version changed, search over the code, more likely
   under ``pkg/k8s``, if there is code that can be removed which specifically
   exists for the compatibility of the previous Kubernetes minimal version
   supported.

#. If the minimal supported version changed, update the field
   ``MinimalVersionConstraint`` in ``pkg/k8s/version/version.go``

#. Sync all "``slim``" types by following the instructions in
   ``pkg/k8s/slim/README.md``.  The overall goal is to update changed fields or
   deprecated fields from the upstream code. New functions / fields / structs
   added in upstream that are not used in Cilium, can be removed.

#. Make sure the workflows used on all PRs are running with the new Kubernetes
   version by default. Make sure the files ``contributing/testing/{ci,e2e}.rst``
   are up to date with these changes.

#. Update documentation files:
   - ``Documentation/contributing/testing/e2e.rst``
   - ``Documentation/network/kubernetes/compatibility.rst``
   - ``Documentation/network/kubernetes/requirements.rst``

#. Update the Kubernetes version with the newer version in
   - ``test/test_suite_test.go``.
   - ``.github/actions/ginkgo/main-prs.yaml``
   - ``.github/actions/ginkgo/main-scheduled.yaml``
   - ``.github/actions/set-env-variables/action.yml``
   - ``contrib/scripts/devcontainer-setup.sh``
   - ``.github/actions/ginkgo/main-focus.yaml``

#. Add the new coredns files specific for the Kubernetes version,
   for ``1.19`` is ``test/provision/manifest/1.19``. The coredns deployment
   files can be found upstream as mentioned in the previous k8s version
   coredns files. Perform a diff with the previous versions to check which
   changes are required for our CI and which changes were added upstream.

#. Update the constraint in the function ``getK8sSupportedConstraints``, that
   exists in the ``test/helpers/utils.go``, with the new Kubernetes version that
   Cilium supports. It is possible that a new ``IsCiliumV1*`` var in that file
   is required as well.

#. Bump the kindest/node version in
   ``.github/actions/ginkgo/main-k8s-versions.yaml``.

#. Run ``./contrib/scripts/check-k8s-code-gen.sh``

#. Run ``go mod vendor && go mod tidy``

#. Run ``./contrib/scripts/check-k8s-code-gen.sh`` (again)

#. Run ``make -C Documentation update-helm-values``

#. Compile the code locally to make sure all the library updates didn't removed
   any used code.

#. Provision a new dev VM to check if the provisioning scripts work correctly
   with the new k8s version.

#. Run ``git add vendor/ test/provision/manifest/ Documentation/ && git commit -sam "Update k8s tests and libraries to v1.28.0-rc.0"``

#. Submit all your changes into a new PR. Ensure the PR is opened against a
   branch in ``cilium/cilium`` and *not* a fork. Otherwise, CI is not triggered
   properly. Please open a thread on #development if you do not have
   permissions to create a branch in ``cilium/cilium``.

#. Ensure that the target CI workflows are running and passing after updating
   the target k8s versions in the GitHub action workflows.

#. Once CI is green and PR has been merged, ping the CI team again so that they
   update the `Cilium CI matrix`_, ``.github/maintainers-little-helper.yaml``,
   and GitHub required PR checks accordingly.

.. _Cilium CI matrix: https://docs.google.com/spreadsheets/d/1TThkqvVZxaqLR-Ela4ZrcJ0lrTJByCqrbdCjnI32_X0

Patch version
~~~~~~~~~~~~~

#. Submit all your changes into a new PR.

Making changes to the Helm chart
--------------------------------

The Helm chart is located in the ``install/kubernetes`` directory. The
``values.yaml.tmpl`` file contains the values for the Helm chart which are being used into the ``values.yaml`` file.

To prepare your changes you need to run the make scripts for the chart:

.. code-block:: shell-session

   $ make -C install/kubernetes

This does all needed steps in one command. Your change to the Helm chart is now ready to be submitted!

You can also run them one by one using the individual targets below.

When updating or adding a value they can be synced to the ``values.yaml`` file by running the following command:

.. code-block:: shell-session

   $ make -C install/kubernetes cilium/values.yaml

Before submitting the changes the ``README.md`` file needs to be updated, this can be done using the ``docs`` target:

.. code-block:: shell-session

   $ make -C install/kubernetes docs

At last you might want to check the chart using the ``lint`` target:

.. code-block:: shell-session

   $ make -C install/kubernetes lint


Optional: Docker and IPv6
-------------------------

Note that these instructions are useful to you if you care about having IPv6
addresses for your Docker containers.

If you'd like IPv6 addresses, you will need to follow these steps:

1) Edit ``/etc/docker/daemon.json`` and set the ``ipv6`` key to ``true``.

   .. code-block:: json

      {
        "ipv6": true
      }


   If that doesn't work alone, try assigning a fixed range. Many people have
   reported trouble with IPv6 and Docker. `Source here.
   <https://github.com/moby/moby/issues/29443#issuecomment-495808871>`_

   .. code-block:: json

      {
        "ipv6": true,
        "fixed-cidr-v6": "2001:db8:1::/64"
      }


   And then:

   .. code-block:: shell-session

    ip -6 route add 2001:db8:1::/64 dev docker0
    sysctl net.ipv6.conf.default.forwarding=1
    sysctl net.ipv6.conf.all.forwarding=1


2) Restart the docker daemon to pick up the new configuration.

3) The new command for creating a network managed by Cilium:

   .. code-block:: shell-session

      $ docker network create --ipv6 --driver cilium --ipam-driver cilium cilium-net


Now new containers will have an IPv6 address assigned to them.

Debugging
---------

Datapath code
~~~~~~~~~~~~~

The tool ``cilium-dbg monitor`` can also be used to retrieve debugging information
from the eBPF based datapath. To enable all log messages:

- Start the ``cilium-agent`` with ``--debug-verbose=datapath``, or
- Run ``cilium-dbg config debug=true debugLB=true`` from an already running agent.

These options enable logging functions in the datapath: ``cilium_dbg()``,
``cilium_dbg_lb()`` and ``printk()``.

.. note::

   The ``printk()`` logging function is used by the developer to debug the datapath outside of the ``cilium
   monitor``.  In this case, ``bpftool prog tracelog`` can be used to retrieve
   debugging information from the eBPF based datapath. Both ``cilium_dbg()`` and
   ``printk()`` functions are available from the ``bpf/lib/dbg.h`` header file.

The image below shows the options that could be used as startup options by
``cilium-agent`` (see upper blue box) or could be changed at runtime by running
``cilium-dbg config <option(s)>`` for an already running agent (see lower blue box).
Along with each option, there is one or more logging function associated with it:
``cilium_dbg()`` and ``printk()``, for ``DEBUG`` and ``cilium_dbg_lb()`` for
``DEBUG_LB``.

.. image:: _static/cilium-debug-datapath-options.svg
  :align: center
  :alt: Cilium debug datapath options

.. note::

   If you need to enable the ``LB_DEBUG`` for an already running agent by running
   ``cilium-dbg config debugLB=true``, you must pass the option ``debug=true`` along.

Debugging of an individual endpoint can be enabled by running
``cilium-dbg endpoint config ID debug=true``. Running ``cilium-dbg monitor -v`` will
print the normal form of monitor output along with debug messages:

.. code-block:: shell-session

   $ cilium-dbg endpoint config 731 debug=true
   Endpoint 731 configuration updated successfully
   $ cilium-dbg monitor -v
   Press Ctrl-C to quit
   level=info msg="Initializing dissection cache..." subsys=monitor
   <- endpoint 745 flow 0x6851276 identity 4->0 state new ifindex 0 orig-ip 0.0.0.0: 8e:3c:a3:67:cc:1e -> 16:f9:cd:dc:87:e5 ARP
   -> lxc_health: 16:f9:cd:dc:87:e5 -> 8e:3c:a3:67:cc:1e ARP
   CPU 00: MARK 0xbbe3d555 FROM 0 DEBUG: Inheriting identity=1 from stack
   <- host flow 0xbbe3d555 identity 1->0 state new ifindex 0 orig-ip 0.0.0.0: 10.11.251.76:57896 -> 10.11.166.21:4240 tcp ACK
   CPU 00: MARK 0xbbe3d555 FROM 0 DEBUG: Successfully mapped addr=10.11.251.76 to identity=1
   CPU 00: MARK 0xbbe3d555 FROM 0 DEBUG: Attempting local delivery for container id 745 from seclabel 1
   CPU 00: MARK 0xbbe3d555 FROM 745 DEBUG: Conntrack lookup 1/2: src=10.11.251.76:57896 dst=10.11.166.21:4240
   CPU 00: MARK 0xbbe3d555 FROM 745 DEBUG: Conntrack lookup 2/2: nexthdr=6 flags=0
   CPU 00: MARK 0xbbe3d555 FROM 745 DEBUG: CT entry found lifetime=21925, revnat=0
   CPU 00: MARK 0xbbe3d555 FROM 745 DEBUG: CT verdict: Established, revnat=0
   -> endpoint 745 flow 0xbbe3d555 identity 1->4 state established ifindex lxc_health orig-ip 10.11.251.76: 10.11.251.76:57896 -> 10.11.166.21:4240 tcp ACK

Passing ``-v -v`` supports deeper detail, for example:

.. code-block:: shell-session

    $ cilium-dbg endpoint config 3978 debug=true
    Endpoint 3978 configuration updated successfully
    $ cilium-dbg monitor -v -v --hex
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


One of the most common issues when developing datapath code is that the eBPF
code cannot be loaded into the kernel. This frequently manifests as the
endpoints appearing in the "not-ready" state and never switching out of it:

.. code-block:: shell-session

    $ cilium-dbg endpoint list
    ENDPOINT   POLICY        IDENTITY   LABELS (source:key[=value])   IPv6                     IPv4            STATUS
               ENFORCEMENT
    48896      Disabled      266        container:id.server           fd02::c0a8:210b:0:bf00   10.11.13.37     not-ready
    60670      Disabled      267        container:id.client           fd02::c0a8:210b:0:ecfe   10.11.167.158   not-ready

Running ``cilium-dbg endpoint get`` for one of the endpoints will provide a
description of known state about it, which includes eBPF verification logs.

The files under ``/var/run/cilium/state`` provide context about how the eBPF
datapath is managed and set up. The .h files describe specific configurations
used for eBPF program compilation. The numbered directories describe
endpoint-specific state, including header configuration files and eBPF binaries.

Current eBPF map state for particular programs is held under ``/sys/fs/bpf/``,
and the `bpf-map <https://github.com/cilium/bpf-map>`_ utility can be useful
for debugging what is going on inside them, for example:

.. code-block:: shell-session

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



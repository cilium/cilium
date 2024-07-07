.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _testsuite:

End-To-End Connectivity Testing
===============================

Introduction
~~~~~~~~~~~~

Cilium uses `cilium-cli connectivity tests
<https://github.com/cilium/cilium-cli/#connectivity-check>`_
for implementing and running end-to-end tests which test Cilium all the way
from the API level (for example, importing policies, CLI) to the datapath (in order words, whether
policy that is imported is enforced accordingly in the datapath).

Running End-To-End Connectivity Tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The connectivity tests are implemented in such a way that they can be run against
any K8s cluster running Cilium. The built-in feature detection allows the testing
framework to automatically skip tests when a required test condition cannot be met
(for example, skip the Egress Gateway tests if the Egress Gateway feature is disabled).

Running tests locally
^^^^^^^^^^^^^^^^^^^^^

.. include:: /installation/cli-download.rst

Alternatively, ``Cilium CLI`` can be manually built and installed by fetching
``https://github.com/cilium/cilium-cli``, and then running ``make install``.

Next, you need a Kubernetes cluster to run Cilium. The easiest way to create one
is to use `kind <https://github.com/kubernetes-sigs/kind>`_. Cilium provides
a wrapper script which simplifies creating K8s cluster with ``kind``. For example,
to create a cluster consisting of 1 control-plane node, 3 worker nodes, without
kube-proxy, and with ``DualStack`` enabled:

.. code-block:: shell-session

    $ cd cilium/
    $ ./contrib/scripts/kind.sh "" 3 "" "" "none" "dual"
    ...
    Kind is up! Time to install cilium:
    make kind-image
    make kind-install-cilium

Afterwards, you need to install Cilium. The preferred way is to use
`cilium-cli install <https://github.com/cilium/cilium-cli/#install-cilium>`_,
as it is able to automate some steps (e.g., detecting ``kube-apiserver`` endpoint
address which otherwise needs to be specified when running w/o ``kube-proxy``, or
set an annotation to a K8s worker node to prevent Cilium from being scheduled on it).

Assuming that Cilium was built with:

.. code-block:: shell-session

    $ cd cilium/
    $ make kind-image
    ...
    ^^^ Images pushed, multi-arch manifest should be above. ^^^

You can install Cilium with the following command:

.. code-block:: shell-session

    $ cilium install --wait \
        --chart-directory=$GOPATH/src/github.com/cilium/cilium/install/kubernetes/cilium \
        --set image.override=localhost:5000/cilium/cilium-dev:local \
        --set image.pullPolicy=Never \
        --set operator.image.override=localhost:5000/cilium/operator-generic:local \
        --set operator.image.pullPolicy=Never \
        --set routingMode=tunnel \
        --set tunnelProtocol=vxlan \
        --nodes-without-cilium
    ...
    ⌛ Waiting for Cilium to be installed and ready...
    ✅ Cilium was successfully installed! Run 'cilium status' to view installation health

Finally, to run tests:

.. code-block:: shell-session

    $ cilium connectivity test
    ...
    ✅ All 32 tests (263 actions) successful, 2 tests skipped, 1 scenarios skipped.

Alternatively, you can select which tests to run:

.. code-block:: shell-session

    $ cilium connectivity test --test north-south-loadbalancing
    ...
    [=] Test [north-south-loadbalancing]

Running tests in VM
^^^^^^^^^^^^^^^^^^^

To run Cilium and the connectivity tests in a virtual machine, one can use
`little-vm-helper (LVH) <https://github.com/cilium/little-vm-helper>`_. The
project provides a runner of qemu-based VMs, a builder of VM images,
and a registry containing pre-built VM images.

First, install the LVH cli tool:

.. code-block:: shell-session

     $ go install github.com/cilium/little-vm-helper/cmd/lvh@latest
     $ lvh --help
     ...
     Use "lvh [command] --help" for more information about a command.

Second, fetch a VM image:

.. code-block:: shell-session

    $ lvh images pull quay.io/lvh-images/kind:6.1-main --dir .

See `<https://quay.io/repository/lvh-images/kind?tab=tags>`_ for all available
images. To build a new VM image (or to update any existing) please refer to
`little-vm-helper-images <https://github.com/cilium/little-vm-helper-images>`_.

Next, start a VM:

.. code-block:: shell-session

    $ lvh run --image ./images/kind_6.1.qcow2 --host-mount $GOPATH/src/github.com/cilium/ --daemonize -p 2222:22 --cpu=3 --mem=6G

.. _test_cilium_on_lvh:

Finally, you can SSH into the VM to start a K8s cluster, install Cilium, and finally run the connectivity tests:

.. code-block:: shell-session

    $ ssh -p 2222 -o "StrictHostKeyChecking=no" root@localhost
    # cd /host/cilium
    # git config --global --add safe.directory /host/cilium
    # ./contrib/scripts/kind.sh "" 3 "" "" "none" "dual"
    # cd /host/cilium-cli
    # ./cilium install --wait \
        --chart-directory=../cilium/install/kubernetes/cilium \
        --version=v1.13.2 \
        --set routingMode=tunnel \
        --set tunnelProtocol=vxlan \
        --nodes-without-cilium
    # ./cilium connectivity test
    ...
    ✅ All 32 tests (263 actions) successful, 2 tests skipped, 1 scenarios skipped.

To stop the VM, run from the host:

.. code-block:: shell-session

    $ pkill qemu-system-x86

Running tests in a VM with a custom kernel
""""""""""""""""""""""""""""""""""""""""""

It is possible to test Cilium on an LVH VM with a custom built Linux kernel (for example,
for fast testing iterations when doing kernel development work for Cilium features).

First, to configure and to build the kernel:

.. code-block:: shell-session

   $ git clone --depth=1 https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git
   $ cd bpf-next/

   # configure kernel, so that it can be run in LVH VM:
   $ git clone https://github.com/cilium/little-vm-helper-images
   $ cat ../little-vm-helper-images/_data/kernels.json | \
        jq -r '.common_opts.[] | (.[0])+" "+(.[1])' | \
        xargs ./scripts/config

   $ make -j$(nproc)

Second, start the LVH VM with the custom kernel:

.. code-block:: shell-session

   $ lvh run --image ./images/kind_bpf-next.qcow2 \
        --host-mount $(pwd) \
        --kernel ./bpf-next/arch/x86_64/boot/bzImage \
        --daemonize -p 2222:22 --cpu=3 --mem=6G \

Third, SSH into the VM, and install the custom kernel modules (this step is no longer
required once `little-vm-helper#117 <https://github.com/cilium/little-vm-helper/issues/117>`_
has been resolved):

.. code-block:: shell-session

    $ ssh -p 2222 -o "StrictHostKeyChecking=no" root@localhost
    # cd /host/bpf-next
    # make modules_install

Finally, you can use the instructions from :ref:`the previous chapter<test_cilium_on_lvh>` to run and to test Cilium.

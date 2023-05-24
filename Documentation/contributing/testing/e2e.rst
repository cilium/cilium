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
from the API level (e.g. importing policies, CLI) to the datapath (i.e, whether
policy that is imported is enforced accordingly in the datapath).

Running End-To-End Connectivity Tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The connectivity tests are implemented in such a way that they can be run against
any K8s cluster running Cilium. The built-in feature detection allows the testing 
framework to automatically skip tests when a required test condition cannot be met
(e.g., skip the Egress Gateway tests if the Egress Gateway feature is disabled).

Running tests locally
^^^^^^^^^^^^^^^^^^^^^


Before running the connectivity tests you need to install `Cilium CLI <https://github.com/cilium/cilium-cli/>`_ .
Alternatively, ``Cilium CLI`` can be manually built and installed by fetching
`https://github.com/cilium/cilium-cli`, and then running ``make install``.

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

Assuming that Cilium was built and pushed to a local registry with:

.. code-block:: shell-session

    $ cd cilium/
    $ make kind-image
    ...
    ^^^ Images pushed, multi-arch manifest should be above. ^^^

You can install Cilium with the following:

.. code-block:: shell-session

    $ cilium install --wait --rollback=false \
        --chart-directory=$GOPATH/src/github.com/cilium/cilium/install/kubernetes/cilium \
        --helm-set=image.override=localhost:5000/cilium/cilium-dev:local \
        --helm-set=image.pullPolicy=Never \
        --helm-set=operator.image.override=localhost:5000/cilium/operator-generic:local \
        --helm-set=operator.image.pullPolicy=Never \
        --helm-set-string=tunnel=vxlan \
        --nodes-without-cilium=kind-worker3
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

    $ mkdir images/
    $ docker run -v $(pwd)/images:/mnt/images \
        quay.io/lvh-images/kind:6.0-main \
        cp /data/images/kind_6.0.qcow2.zst /mnt/images
    $ cd images/
    $ zstd -d kind_6.0.qcow2.zst

Alternatively, you can use the ``scripts/pull_image.sh``:

.. code-block:: shell-session

    $ mkdir images/
    $ git clone https://github.com/cilium/little-vm-helper
    $ IMAGE_DIR=./images ./little-vm-helper/scripts/pull_image.sh quay.io/lvh-images/kind:6.0-main

See `<https://quay.io/organization/lvh-images/kind?tab=tags>`_ for all available
images. To build a new VM image (or to update any existing) please refer to
`little-vm-helper-images <https://github.com/cilium/little-vm-helper-images>`_.

Next, start a VM:

.. code-block:: shell-session

    $ lvh run --image ./images/kind_6.0.qcow2 --host-mount $GOPATH/src/github.com/cilium/ --daemonize -p 2222:22 --cpu=3 --mem=6G

Finally, you can SSH into the VM to start a K8s cluster, install Cilium, and finally run the connectivity tests:

.. code-block:: shell-session

    $ ssh -p 2222 -o "StrictHostKeyChecking=no" root@localhost
    # echo "nameserver 1.1.1.1" > /etc/resolv.conf
    # cd /host/cilium
    # git config --global --add safe.directory /host/cilium
    # ./contrib/scripts/kind.sh "" 3 "" "" "none" "dual"
    # cd /host/cilium-cli
    # ./cilium install --wait --rollback=false \
        --chart-directory=../cilium/install/kubernetes/cilium \
        --version=v1.13.2 \
        --helm-set-string=tunnel=vxlan \
        --nodes-without-cilium=kind-worker3
    # ./cilium connectivity test
    ...
    ✅ All 32 tests (263 actions) successful, 2 tests skipped, 1 scenarios skipped.

To stop the VM, run from the host:

.. code-block:: shell-session

    $ pkill qemu-system-x86

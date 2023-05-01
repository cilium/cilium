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

Before running the connectivity tests you need to install `Cilium CLI <https://github.com/cilium/cilium-cli#installation>`_.
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

.. code_block:: shell-session

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

.. code_block:: shell-session

    $ cilium connectivity test
    ...
    ✅ All 32 tests (263 actions) successful, 2 tests skipped, 1 scenarios skipped.

Alternatively, you can select which tests to run:

.. code_block:: shell-session
   
    $ cilium connectivity test --test north-south-loadbalancing
    ...
    [=] Test [north-south-loadbalancing]
    ......

Running tests in VM
^^^^^^^^^^^^^^^^^^^

TODO

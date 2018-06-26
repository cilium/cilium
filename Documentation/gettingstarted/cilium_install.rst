.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
      http://docs.cilium.io

Step 1: Install Cilium
======================

The next step is to install Cilium into your Kubernetes cluster.
Cilium installation leverages the `Kubernetes Daemon Set
<https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/>`_
abstraction, which will deploy one Cilium pod per cluster node.  This
Cilium pod will run in the ``kube-system`` namespace along with all
other system relevant daemons and services.  The Cilium pod will run
both the Cilium agent and the Cilium CNI plugin.

Choose the installation instructions for the environment in which you are
deploying Cilium.

Docker Based
------------

`install_cilium_docker`

CRI-O Based
-----------

`install_cilium_crio`

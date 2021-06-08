.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_kind:

**************************
Getting Started Using Kind
**************************

This guide uses `kind <https://kind.sigs.k8s.io/>`_ to demonstrate deployment
and operation of Cilium in a multi-node Kubernetes cluster running locally on
Docker.

Install Dependencies
====================

.. include:: kind-install-deps.rst

Configure kind
==============

.. include:: kind-configure.rst

Create a cluster
================

.. include:: kind-create-cluster.rst

.. _kind_install_cilium:

Install Cilium
==============

.. include:: k8s-install-download-release.rst
.. include:: kind-preload.rst

Then, install Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set nodeinit.enabled=true \\
      --set kubeProxyReplacement=partial \\
      --set hostServices.enabled=false \\
      --set externalIPs.enabled=true \\
      --set nodePort.enabled=true \\
      --set hostPort.enabled=true \\
      --set bpf.masquerade=false \\
      --set image.pullPolicy=IfNotPresent \\
      --set ipam.mode=kubernetes

.. note::

   To fully enable Cilium's kube-proxy replacement (:ref:`kubeproxy-free`), cgroup v1
   controllers ``net_cls`` and ``net_prio`` have to be disabled, or cgroup v1 has
   to be disabled (e.g. by setting the kernel ``cgroup_no_v1="all"`` parameter).

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst

Troubleshooting
===============

Unable to contact k8s api-server
--------------------------------

In the :ref:`Cilium agent logs <ts_agent_logs>` you will see::

    level=info msg="Establishing connection to apiserver" host="https://10.96.0.1:443" subsys=k8s
    level=error msg="Unable to contact k8s api-server" error="Get https://10.96.0.1:443/api/v1/namespaces/kube-system: dial tcp 10.96.0.1:443: connect: no route to host" ipAddr="https://10.96.0.1:443" subsys=k8s
    level=fatal msg="Unable to initialize Kubernetes subsystem" error="unable to create k8s client: unable to create k8s client: Get https://10.96.0.1:443/api/v1/namespaces/kube-system: dial tcp 10.96.0.1:443: connect: no route to host" subsys=daemon

As Kind is running nodes as containers in Docker, they're sharing your host machines' kernel.
If :ref:`host-services` wasn't disabled, the eBPF programs attached by Cilium may be out of date
and no longer routing api-server requests to the current ``kind-control-plane`` container.

Recreating the kind cluster and using the helm command :ref:`kind_install_cilium` will detach the
inaccurate eBPF programs.

.. _gs_kind_cluster_mesh:

Cluster Mesh
============

With Kind we can simulate Cluster Mesh in a sandbox too.

Kind Configuration
------------------

This time we need to create (2) ``config.yaml``, one for each kubernetes cluster.
We will explicitly configure their ``pod-network-cidr`` and ``service-cidr`` to not overlap.

Example ``kind-cluster1.yaml``:

.. code-block:: yaml

    kind: Cluster
    apiVersion: kind.x-k8s.io/v1alpha4
    nodes:
    - role: control-plane
    - role: worker
    - role: worker
    - role: worker
    networking:
      disableDefaultCNI: true
      podSubnet: "10.0.0.0/16"
      serviceSubnet: "10.1.0.0/16"

Example ``kind-cluster2.yaml``:

.. code-block:: yaml

    kind: Cluster
    apiVersion: kind.x-k8s.io/v1alpha4
    nodes:
    - role: control-plane
    - role: worker
    - role: worker
    - role: worker
    networking:
      disableDefaultCNI: true
      podSubnet: "10.2.0.0/16"
      serviceSubnet: "10.3.0.0/16"

Create Kind Clusters
--------------------

We can now create the respective clusters:

.. code-block:: shell-session

    kind create cluster --name=cluster1 --config=kind-cluster1.yaml
    kind create cluster --name=cluster2 --config=kind-cluster2.yaml

Deploy Cilium
-------------

This is the same helm command as from :ref:`kind_install_cilium`. However
we're enabling managed etcd and setting both ``cluster-name`` and
``cluster-id`` for each cluster.

Make sure context is set to ``kind-cluster2`` cluster.

.. code-block:: shell-session

   kubectl config use-context kind-cluster2

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set nodeinit.enabled=true \\
      --set kubeProxyReplacement=partial \\
      --set hostServices.enabled=false \\
      --set externalIPs.enabled=true \\
      --set nodePort.enabled=true \\
      --set hostPort.enabled=true \\
      --set cluster.name=cluster2 \\
      --set cluster.id=2

Change the kubectl context to ``kind-cluster1`` cluster:

.. code-block:: shell-session

   kubectl config use-context kind-cluster1

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set nodeinit.enabled=true \\
      --set kubeProxyReplacement=partial \\
      --set hostServices.enabled=false \\
      --set externalIPs.enabled=true \\
      --set nodePort.enabled=true \\
      --set hostPort.enabled=true \\
      --set cluster.name=cluster1 \\
      --set cluster.id=1

Setting up Cluster Mesh
------------------------

We can complete setup by following the Cluster Mesh guide with :ref:`gs_clustermesh`.
For Kind, we'll want to deploy the ``NodePort`` service into the ``kube-system`` namespace.

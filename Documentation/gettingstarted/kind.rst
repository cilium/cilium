.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_kind:

**************************
Getting Started Using Kind
**************************

This guide uses `kind <https://kind.sigs.k8s.io/>`_ to demonstrate deployment
and operation of Cilium in a multi-node Kubernetes cluster.

Kind requires docker to be installed and running.

Install Dependencies
====================

1. Install ``docker`` stable as described in: `Install Docker Engine <https://docs.docker.com/engine/install/>`_

2. Install ``kubectl`` version >= v1.14.0 as described in the `Kubernetes Docs <https://kubernetes.io/docs/tasks/tools/install-kubectl/>`_

3. Install ``helm`` >= v3.0.3 per Helm documentation: `Installing Helm <https://helm.sh/docs/intro/install/>`_

4. Install ``kind`` >= v0.7.0 per kind documentation: `Installation and Usage <https://kind.sigs.k8s.io/#installation-and-usage>`_

Kind Configuration
==================

Kind doesn't use flags for configuration. Instead it uses YAML configuration that is very similar to Kubernetes.

Create a ``kind-config.yaml`` file based on the following template. The template will create 3 node + 1 apiserver
cluster with the latest version of kubernetes from when the kind release was created.

.. code:: yaml

    kind: Cluster
    apiVersion: kind.x-k8s.io/v1alpha4
    nodes:
    - role: control-plane
    - role: worker
    - role: worker
    - role: worker
    networking:
      disableDefaultCNI: true

To change the version of kubernetes being run,  ``image`` has to be defined for each node. See
the `Node Configration <https://kind.sigs.k8s.io/docs/user/configuration/#nodes>`_ documentation.

Start Kind
==========

Pass the ``kind-config.yaml`` you created with the ``--config`` flag of kind.

.. code:: bash

    kind create cluster --config=kind-config.yaml

This will add a ``kind-kind`` context to ``KUBECONFIG`` or if unset, ``${HOME}/.kube/config``

.. code:: bash

    kubectl cluster-info --context kind-kind

.. _kind_install_cilium:

Install Cilium
==============

.. include:: k8s-install-download-release.rst


**(optional, but recommended)** Pre-load Cilium images into the kind cluster so each worker doesn't have to pull them.

.. parsed-literal::

  docker pull cilium/cilium:|IMAGE_TAG|
  kind load docker-image cilium/cilium:|IMAGE_TAG|

Install Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set global.nodeinit.enabled=true \\
      --set global.kubeProxyReplacement=partial \\
      --set global.hostServices.enabled=false \\
      --set global.externalIPs.enabled=true \\
      --set global.nodePort.enabled=true \\
      --set global.hostPort.enabled=true \\
      --set global.pullPolicy=IfNotPresent

.. include:: k8s-install-validate.rst
.. include:: hubble-enable.rst

Next steps
==========

Now that you have a Kubernetes cluster with Cilium up and running, you can take
a couple of next steps to explore various capabilities:

* :ref:`gs_http`
* :ref:`gs_dns`
* :ref:`gs_cassandra`
* :ref:`gs_kafka`

Troubleshooting
===============

Unable to contact k8s api-server
--------------------------------

In the :ref:`Cilum agent logs <ts_agent_logs>` you will see::

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

.. code:: yaml

    kind: Cluster
    apiVersion: kind.x-k8s.io/v1alpha4
    nodes:
    - role: control-plane
    - role: worker
    - role: worker
    - role: worker
    networking:
      disableDefaultCNI: true
      podSubnet: 10.0.0.0/16
      serviceSubnet: 10.1.0.0/16

Example ``kind-cluster2.yaml``:

.. code:: yaml

    kind: Cluster
    apiVersion: kind.x-k8s.io/v1alpha4
    nodes:
    - role: control-plane
    - role: worker
    - role: worker
    - role: worker
    networking:
      disableDefaultCNI: true
      podSubnet: 10.2.0.0/16
      serviceSubnet: 10.3.0.0/16

Create Kind Clusters
--------------------

We can now create the respective clusters:

.. code:: bash

    kind create cluster --name=cluster1 --config=kind-cluster1.yaml
    kind create cluster --name=cluster2 --config=kind-cluster2.yaml

Deploy Cilium
-------------

This is the same helm command as from :ref:`kind_install_cilium`. However
we're enabling managed etcd and setting both ``cluster-name`` and
``cluster-id`` for each cluster.

Make sure context is set to ``kind-cluster2`` cluster.

.. code:: bash

   kubectl config use-context kind-cluster2

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set global.nodeinit.enabled=true \\
      --set global.kubeProxyReplacement=partial \\
      --set global.hostServices.enabled=false \\
      --set global.externalIPs.enabled=true \\
      --set global.nodePort.enabled=true \\
      --set global.hostPort.enabled=true \\
      --set global.etcd.enabled=true \\
      --set global.etcd.managed=true \\
      --set global.identityAllocationMode=kvstore \\
      --set global.cluster.name=cluster2 \\
      --set global.cluster.id=2

Change the kubectl context to ``kind-cluster1`` cluster:

.. code:: bash

   kubectl config use-context kind-cluster1

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set global.nodeinit.enabled=true \\
      --set global.kubeProxyReplacement=partial \\
      --set global.hostServices.enabled=false \\
      --set global.externalIPs.enabled=true \\
      --set global.nodePort.enabled=true \\
      --set global.hostPort.enabled=true \\
      --set global.etcd.enabled=true \\
      --set global.etcd.managed=true \\
      --set global.identityAllocationMode=kvstore \\
      --set global.cluster.name=cluster1 \\
      --set global.cluster.id=1

Setting up Cluster Mesh
------------------------

We can complete setup by following the Cluster Mesh guide with :ref:`gs_clustermesh_expose_etcd`.
For Kind, we'll want to deploy the ``NodePort`` service into the ``kube-system`` namespace.

.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_kind:

***********************
Installation Using Kind
***********************

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
      --set image.pullPolicy=IfNotPresent \\
      --set ipam.mode=kubernetes

.. note::

   To enable Cilium's Socket LB (:ref:`kubeproxy-free`), cgroup v2 needs to be
   enabled, and Kind nodes need to run in separate `cgroup namespaces
   <https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html>`__,
   and these namespaces need to be different from the cgroup namespace
   of the underlying host so that Cilium can attach BPF programs at the right
   cgroup hierarchy. To verify this, run the following commands, and ensure
   that the cgroup values are different:

   .. code-block:: shell-session

      $ docker exec kind-control-plane ls -al /proc/self/ns/cgroup
      lrwxrwxrwx 1 root root 0 Jul 20 19:20 /proc/self/ns/cgroup -> 'cgroup:[4026532461]'

      $ docker exec kind-worker ls -al /proc/self/ns/cgroup
      lrwxrwxrwx 1 root root 0 Jul 20 19:20 /proc/self/ns/cgroup -> 'cgroup:[4026532543]'

      $ ls -al /proc/self/ns/cgroup
      lrwxrwxrwx 1 root root 0 Jul 19 09:38 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'


   One way to enable cgroup v2 is to set the kernel parameter
   ``systemd.unified_cgroup_hierarchy=1``. To enable cgroup namespaces, a container
   runtime needs to configured accordingly. For example in Docker,
   dockerd's ``--default-cgroupns-mode`` has to be set to ``private``.

   Another requirement for the Socket LB on Kind to properly function is that either cgroup v1
   controllers ``net_cls`` and ``net_prio`` are disabled (or cgroup v1 altogether is disabled
   e.g., by setting the kernel parameter ``cgroup_no_v1="all"``), or the host kernel
   should be 5.14 or more recent to include this `fix
   <https://github.com/torvalds/linux/commit/8520e224f547cd070c7c8f97b1fc6d58cff7ccaa>`__.

   See the `Pull Request <https://github.com/cilium/cilium/pull/16259>`__ for more details.

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
If the socket LB wasn't disabled, the eBPF programs attached by Cilium may be out of date
and no longer routing api-server requests to the current ``kind-control-plane`` container.

Recreating the kind cluster and using the helm command :ref:`kind_install_cilium` will detach the
inaccurate eBPF programs.

Crashing Cilium agent pods
--------------------------

Check if Cilium agent pods are crashing with following logs. This may indicate
that you are deploying a kind cluster in an environment where Cilium is already
running (for example, in the Cilium development VM). This can also happen if you
have other overlapping BPF ``cgroup`` type programs attached to the parent ``cgroup``
hierarchy of the kind container nodes. In such cases, either tear down Cilium, or manually
detach the overlapping BPF ``cgroup`` programs running in the parent ``cgroup`` hierarchy
by following the `bpftool documentation <https://manpages.ubuntu.com/manpages/focal/man8/bpftool-cgroup.8.html>`_.
For more information, see the `Pull Request <https://github.com/cilium/cilium/pull/16259>`__.

::

    level=warning msg="+ bpftool cgroup attach /var/run/cilium/cgroupv2 connect6 pinned /sys/fs/bpf/tc/globals/cilium_cgroups_connect6" subsys=datapath-loader
    level=warning msg="Error: failed to attach program" subsys=datapath-loader
    level=warning msg="+ RETCODE=255" subsys=datapath-loader

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

Setting up Cluster Mesh
------------------------

We can deploy Cilium, and complete setup by following the Cluster Mesh guide
with :ref:`gs_clustermesh`. For Kind, we'll want to deploy the ``NodePort`` service into the ``kube-system`` namespace.

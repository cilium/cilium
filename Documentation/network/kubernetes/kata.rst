.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _kata:

***************************
Kata Containers with Cilium
***************************

`Kata Containers <https://katacontainers.io/>`_ is an open source project that
provides a secure container runtime with lightweight virtual machines that feel
and perform like containers, but provide stronger workload isolation using
hardware virtualization technology as a second layer of defense.  Kata
Containers implements OCI runtime spec, just like ``runc`` that is used by
Docker. Cilium can be used along with Kata Containers, using both enables
higher degree of security. Kata Containers enhances security in the compute
layer, while Cilium provides policy and observability in the networking layer.

.. warning::
   Due to the different Kata Containers Networking model, there are limitations
   that can cause connectivity disruptions in Cilium. Please refer to the below
   `Limitations`_ section.

This guide shows how to install Cilium along with Kata Containers. It assumes
that you have already followed the official
`Kata Containers installation user guide <https://github.com/kata-containers/documentation/tree/master/install>`_
to get the Kata Containers runtime up and running on your platform of choice
but that you haven't yet setup Kubernetes.

.. note::
   This guide has been validated by following the Kata Containers guide for
   Google Compute Engine (GCE) and using Ubuntu 18.04 LTS with the packaged
   version of Kata Containers, CRI-containerd and Kubernetes 1.18.3.

Setup Kubernetes with CRI
=========================

Kata Containers runtime is an OCI compatible runtime and cannot directly
interact with the CRI API level. For this reason, it relies on a CRI
implementation to translate CRI into OCI. At the time of writing this guide,
there are two supported ways called CRI-O and CRI-containerd. It is up to you
to choose the one that you want, but you have to pick one.

Refer to the section :ref:`k8s_requirements` for detailed instruction on how to
prepare your Kubernetes environment and make sure to use Kubernetes >= 1.12.
Then, follow the
`official guide to run Kata Containers with Kubernetes <https://github.com/kata-containers/documentation/blob/master/how-to/run-kata-with-k8s.md>`_.

.. note::
   Minimum version of kubernetes 1.12 is required to use the RuntimeClass Feature
   for Kata Container runtime described below.

With your Kubernetes cluster ready, you can now proceed to deploy Cilium.

Deploy Cilium
=============

.. include:: ../../installation/k8s-install-download-release.rst

Deploy Cilium release via Helm:

  .. tabs::

     .. group-tab:: Using CRI-O

        .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set bpf.autoMount.enabled=false

     .. group-tab:: Using CRI-containerd

        .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system

.. warning::

   When using :ref:`kube-proxy-replacement <kubeproxy-free>` or its socket-level
   loadbalancer with Kata containers, the socket-level loadbalancer should be
   disabled for pods by setting ``socketLB.hostNamespaceOnly=true``. See
   :ref:`socketlb-host-netns-only` for more details.

.. include:: ../../installation/k8s-install-validate.rst

Run Kata Containers with Cilium CNI
===================================

Now that your Kubernetes cluster is configured with the Kata Containers runtime
and Cilium as the CNI, you can run a sample workload by following
`these instructions <https://github.com/kata-containers/packaging/tree/master/kata-deploy#run-a-sample-workload>`_.

Limitations
===========

Due to its different `Networking Design Architecture <https://github.com/kata-containers/documentation/blob/master/design/architecture.md#networking>`_,
the Kata runtime adds an additional layer of abstraction inside the Container
Networking Namespace created by Cilium (referred to as "outer"). In that
namespace, Kata creates an isolated VM with an additional Container Networking
Namespace (referred to as "inside") to host the requested Pod, as depicted below.

.. image:: https://raw.githubusercontent.com/kata-containers/documentation/refs/heads/master/design/arch-images/network.png
   :alt: Kata Container Networking Architecture


Upon the outer Container Networking Namespace creation, the Cilium CNI
performs the following two actions:

1. creates the ``eth0`` interface with the same ``device MTU`` of either the detected
   underlying network, or the MTU specified in the Cilium ConfigMap;
2. adjusts the ``default route MTU`` (computed as ``device MTU - overhead``) to account
   for the additional networking overhead given by the Cilium configuration
   (ex. +50B for VXLAN, +80B for WireGuard, etc.).

However, during the inner Container Networking Namespace creation (i.e., the pod
inside the VM), only the outer ``eth0 device MTU`` (1) is copied over by Kata to
the inner ``eth0``, while the ``default route MTU`` (2) is ignored. For this reason,
depending on the types of connections, users might experience performance degradation
or even packet drops between traditional pods and KataPod connections due to
multiple (unexpected) fragmentation.

There are currently two possible workarounds, with (b) being preferred:

a. set a lower MTU value in the Cilium ConfigMap to account for the overhead.
   This would allow the KataPod to have a lower device MTU and prevent unwanted
   fragmentation. However, this is not recommended as it would have a relevant
   impact on all the other types of communications (ex. traditional pod-to-pod,
   pod-to-node, etc.) due to the lower device MTU value being set on all the
   Cilium-managed interfaces.

b. modify the KataPod deployment by adding an ``initContainer`` (with NET_ADMIN)
   to adjust the route MTU inside the inner pod. This would not only align the
   KataPod configuration to all the other pods, but also it would not harm
   all the other types of connections, given that it is a self-contained
   solution in the KataPod itself. The correct ``route MTU`` value to set can be
   either manually computed or retrieved by issuing ``ip route`` on a Cilium Pod
   (or inside a traditional pod). Here follows an example of a KataPod deployment
   (``runtimeClassName: kata-clh``) on a cluster with only Cilium VXLAN enabled
   (``route MTU = 1500B - 50B = 1450``):

   .. code-block:: yaml

      apiVersion: v1
      kind: Pod
      metadata:
        name: nginx-pod
        labels:
          app: nginx
      spec:
        runtimeClassName: kata-clh
        containers:
          - name: nginx
            image: nginx:latest
            ports:
              - containerPort: 80
        initContainers:
          - name: set-mtu
            image: busybox:latest
            command:
              - sh
              - -c
              - |
                DEFAULT="$(ip route show default)"
                ip route replace "$DEFAULT" mtu 1450
            securityContext:
              capabilities:
                add:
                  - NET_ADMIN


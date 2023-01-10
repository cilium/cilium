.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_intro:

************
Introduction
************

What does Cilium provide in your Kubernetes Cluster?
====================================================

The following functionality is provided as you run Cilium in your Kubernetes
cluster:

* :term:`CNI` plugin support to provide pod_connectivity_ with
  `multi_host_networking`.
* Identity based implementation of the `NetworkPolicy` resource to isolate :term:`pod<Pod>`
  to pod connectivity on Layer 3 and 4.
* An extension to NetworkPolicy in the form of a :term:`CustomResourceDefinition`
  which extends policy control to add:

  * Layer 7 policy enforcement on ingress and egress for the following
    application protocols:

    * HTTP
    * Kafka
  * Egress support for CIDRs to secure access to external services
  * Enforcement to external headless services to automatically restrict to the
    set of Kubernetes endpoints configured for a service.
* ClusterIP implementation to provide distributed load-balancing for pod to pod
  traffic.
* Fully compatible with existing kube-proxy model

.. _pod_connectivity:

Pod-to-Pod Connectivity
=======================

In Kubernetes, containers are deployed within units referred to as :term:`Pods<Pod>`, which
include one or more containers reachable via a single IP address.  With Cilium,
each Pod gets an IP address from the node prefix of the Linux node running the
Pod. See :ref:`address_management` for additional details. In the absence of any
network security policies, all Pods can reach each other.

Pod IP addresses are typically local to the Kubernetes cluster. If pods need to
reach services outside the cluster as a client, the network traffic is
automatically masqueraded as it leaves the node.

Service Load-balancing
======================

Kubernetes has developed the Services abstraction which provides the user the
ability to load balance network traffic to different pods. This abstraction
allows the pods reaching out to other pods by a single IP address, a virtual IP
address, without knowing all the pods that are running that particular service.

Without Cilium, kube-proxy is installed on every node, watches for endpoints
and services addition and removal on the kube-master which allows it to apply
the necessary enforcement on iptables. Thus, the received and sent traffic from
and to the pods are properly routed to the node and port serving for that
service. For more information you can check out the kubernetes user guide for
`Services <https://kubernetes.io/docs/concepts/services-networking/service/>`_.

When implementing ClusterIP, Cilium acts on the same principles as kube-proxy,
it watches for services addition or removal, but instead of doing the
enforcement on the iptables, it updates eBPF map entries on each node. For more
information, see the `Pull Request
<https://github.com/cilium/cilium/pull/109>`__.

Further Reading
===============

The Kubernetes documentation contains more background on the `Kubernetes
Networking Model
<https://kubernetes.io/docs/concepts/cluster-administration/networking/>`_ and
`Kubernetes Network Plugins
<https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/>`_
.


.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_guide:

Getting Started Guides
======================

The following is a list of guides that help you get started with Cilium. The
guides cover the installation and then dive into more detailed topics such as
securing clusters, connecting multiple clusters, monitoring, and
troubleshooting. If you are new to Cilium it is recommended to read the
:ref:`intro` section first to learn about the basic concepts and motivation.

.. _gs_install:

Installation
------------
.. toctree::
   :maxdepth: 1
   :glob:

   k8s-install-default
   k8s-install-helm
   k8s-install-advanced
   taints


Observability
-------------

.. toctree::
   :maxdepth: 1
   :glob:

   hubble_setup
   hubble_cli
   hubble

Network Policy Security Tutorials
---------------------------------

.. toctree::
   :maxdepth: 1
   :glob:

   http
   dns
   tls-visibility
   kafka
   grpc
   elasticsearch
   cassandra
   memcached
   aws
   policy-creation
   host-firewall

Advanced Networking
-------------------
.. toctree::
   :maxdepth: 1
   :glob:

   alibabacloud-eni
   kube-router
   bird
   encryption
   kubeproxy-free
   bandwidth-manager
   kata
   ipam
   local-redirect-policy
   bgp
   bgp-control-plane
   egress-gateway
   ciliumendpointslice
   vtep

Cluster Mesh
------------

.. toctree::
   :maxdepth: 1
   :glob:

   clustermesh/clustermesh
   clustermesh/aks-clustermesh-prep
   clustermesh/services
   clustermesh/affinity
   clustermesh/policy
   external-workloads


Service Mesh
------------

.. toctree::
   :maxdepth: 1
   :glob:

   servicemesh/ingress
   servicemesh/l7-traffic-management

Operations
----------

.. toctree::
   :maxdepth: 1
   :glob:

   grafana

Istio
-----

.. toctree::
   :maxdepth: 1
   :glob:

   istio

The best way to get help if you get stuck is to ask a question on `Cilium
Slack`_.  With Cilium contributors across the globe, there is almost always
someone available to help.

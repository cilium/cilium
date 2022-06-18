.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_guide:

Advanced Installation Guides
============================

The following is a list of guides that help you install Cilium. The
guides cover the advanced installation and then dive into more detailed topics such as
securing clusters, connecting multiple clusters, monitoring, and
troubleshooting. If you are new to Cilium it is recommended to read the
:ref:`intro` section first to learn about the basic concepts and motivation.

.. _gs_install:

.. toctree::
   :maxdepth: 1
   :glob:

   taints

Installation with Helm
----------------------
.. toctree::
   :maxdepth: 1
   :glob:

   k8s-install-helm

Installing with K8s distributions
---------------------------------
.. toctree::
   :maxdepth: 1
   :glob:

   k8s-install-external-etcd
   k8s-install-openshift-okd
   k3s
   kind
   cni-chaining

External Installers
-------------------

.. toctree::
   :maxdepth: 1
   :glob:

   k8s-install-kops
   k8s-install-kubespray
   k8s-install-kubeadm
   k8s-install-rancher-existing-nodes
   k8s-install-rke
   rancher-desktop

Installation on Cloud Providers
-------------------------------
.. toctree::
   :maxdepth: 1
   :glob:

   alibabacloud-eni

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

The best way to get help if you get stuck is to ask a question on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_.  With Cilium contributors
across the globe, there is almost always someone available to help.

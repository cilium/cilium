.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _network_root:

Networking
==========

.. _multi host networking:

Networking Concepts
-------------------
.. toctree::
   :maxdepth: 2
   :glob:

   networking/routing
   networking/ipam/index
   networking/masquerading
   networking/fragmentation

Kubernetes Integration
----------------------
.. toctree::
   :maxdepth: 1
   :glob:

   kubernetes/intro
   kubernetes/concepts
   kubernetes/requirements
   kubernetes/configuration
   kubernetes/policy
   kubernetes/ciliumendpoint
   kubernetes/ciliumendpointslice
   kubernetes/compatibility
   kubernetes/troubleshooting

Kubernetes Networking
---------------------
.. toctree::
   :maxdepth: 2
   :glob:

   host-services
   bandwidth-manager
   kata
   ipam
   local-redirect-policy
   ciliumendpointslice

BGP
---

.. toctree::
   :maxdepth: 1
   :glob:

   kube-router
   bird
   bgp
   bgp-control-plane

.. _ebpf_datapath:

eBPF Datapath
-------------

.. toctree::
   :maxdepth: 1
   :glob:

   ebpf/intro
   ebpf/lifeofapacket
   ebpf/maps
   ebpf/iptables

Multi-cluster Networking
------------------------

.. toctree::
   :maxdepth: 1
   :glob:

   clustermesh/intro
   clustermesh/clustermesh
   clustermesh/services
   clustermesh/policy


External networking
-------------------

.. toctree::
   :maxdepth: 1
   :glob:

   external-workloads
   egress-gateway

Istio
-----

.. toctree::
   :maxdepth: 1
   :glob:

   istio


The best way to get help if you get stuck is to ask a question on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_.  With Cilium contributors
across the globe, there is almost always someone available to help.
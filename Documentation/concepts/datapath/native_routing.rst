.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _native_routing:

##############
Native-Routing
##############

The native routing datapath is enabled with ``tunnel: disabled`` and enables
the native packet forwarding mode. The native packet forwarding mode leverages
the routing capabilities of the network Cilium runs on instead of performing
encapsulation.

.. image:: native_routing.png
    :align: center

***************************
Requirements on the network
***************************

* In order to run the native routing mode, the network connecting the hosts on
  which Cilium is running on must be capable of forwarding IP traffic using
  addresses given to pods or other workloads.

* The Linux kernel on the node must be aware on how to forward packets of pods
  or other workloads of all nodes running Cilium. This can be achieved in two
  ways:

  1. The node itself does not know how to route all pod IPs but a router exists
     on the network that knows how to reach all other pods. In this scenario,
     the Linux node is configured to contain a default route to point to such a
     router. This model is used for cloud provider network integration. See
     :ref:`gke_datapath`, :ref:`aws_eni_datapath`, and :ref:`ipam_azure` for
     more details.

  2. Each individual node is made aware of all pod IPs of all other nodes and
     routes are inserted into the Linux kernel routing table to represent this.
     If all nodes share a single L2 network, then this can be taken care of by
     enabling the option ``auto-direct-node-routes: true``. Otherwise, an
     additional system component such as a BGP daemon must be run to distribute
     the routes.  See the guide :ref:`kube-router` on how to achieve this using
     the kube-router project.

************
Masquerading
************

Native routing is typically enabled in the context of a virtual network with
private IP addresses. For any destination outside of the virtual network,
traffic must typically be masqueraded. This is done by setting ``masquerade:
true`` (default). In order to exclude the entire CIDR of the virtual network,
the datapath must be told the CIDR within which native routing is supported.
This is done with the option ``native-routing-cidr: x.x.x.x/y``.

*************
Configuration
*************

The following configuration options must be set to run the datapath in native
routing mode:

* ``tunnel: disabled``: Enable native routing mode
* ``enable-endpoint-routes: true``: Enable per-endpoint routing on the node
* ``native-routing-cidr: x.x.x.x/y``: Set the CIDR in which native routing
  can be performed.

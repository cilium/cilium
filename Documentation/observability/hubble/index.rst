.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _hubble_intro:

*********************************
Network Observability with Hubble
*********************************

Observability is provided by Hubble which enables deep visibility into the
communication and behavior of services as well as the networking infrastructure
in a completely transparent manner. Hubble is able to provide visibility at the
node level, cluster level or even across clusters in a :ref:`Cluster Mesh`
scenario. For an introduction to Hubble and how it relates to Cilium, read the
section :ref:`intro`.

By default, Hubble API operates within the scope of the individual node on which the
Cilium agent runs. This confines the network insights to the traffic observed by the local
Cilium agent. Hubble CLI (``hubble``) can be used to query the Hubble API provided via a local
Unix Domain Socket. The Hubble CLI binary is installed by default on Cilium agent pods.

Upon deploying Hubble Relay, network visibility is provided for the entire cluster or even
multiple clusters in a ClusterMesh scenario. In this mode, Hubble data can be accessed by
directing Hubble CLI (``hubble``) to the Hubble Relay service or via Hubble UI.
Hubble UI is a web interface which enables automatic discovery of the services dependency
graph at the L3/L4 and even L7 layer, allowing user-friendly visualization and filtering
of data flows as a service map.

.. toctree::
   :maxdepth: 2
   :glob:

   setup
   hubble-cli
   hubble-ui
   configuration/export
   configuration/tls

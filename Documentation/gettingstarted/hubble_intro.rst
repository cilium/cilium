.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _observability_intro:

*******************
Hubble Introduction
*******************

Observability is provided by Hubble which enables deep visibility into the
communication and behavior of services as well as the networking infrastructure
in a completely transparent manner. Hubble is able to provide visibility at the
node level, cluster level or even across clusters in a :ref:`Cluster Mesh`
scenario. For an introduction to Hubble and how it relates to Cilium, read the
section :ref:`intro`.

By default, the Hubble API is scoped to each individual node on which the
Cilium agent runs. In other words, networking visibility is only provided for
traffic observed by the local Cilium agent. In this scenario, the only way to
interact with the Hubble API is by using the Hubble CLI (``hubble``) to query
the Hubble API provided via a local Unix Domain Socket.  The Hubble CLI binary
is installed by default on Cilium agent pods.

When Hubble Relay is deployed, Hubble provides full network visibility. In this
scenario, the Hubble Relay service provides a Hubble API which scopes the
entire cluster or even multiple clusters in a ClusterMesh scenario. Hubble data
can be accessed by pointing a Hubble CLI (``hubble``) to the Hubble Relay
service or via Hubble UI. Hubble UI is a web interface which enables automatic
discovery of the services dependency graph at the L3/L4 and even L7 layer,
allowing user-friendly visualization and filtering of data flows as a service
map.

.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bgp_control_plane:

Cilium BGP Control Plane
========================

BGP Control Plane provides a way for Cilium to advertise routes to connected routers by using the
`Border Gateway Protocol`_ (BGP). BGP Control Plane makes Pod networks and/or Services reachable
from outside the cluster for environments that support BGP. Because BGP
Control Plane does not program the :ref:`datapath <ebpf_datapath>`, do not use it to establish
reachability within the cluster.

.. admonition:: Video
  :class: attention

  For more insights on Cilium's BGP, check out `eCHO episode 101: More BGP fun with Cilium <https://www.youtube.com/watch?v=Tv0R6VxyWhc>`__.

.. _Border Gateway Protocol: https://datatracker.ietf.org/doc/html/rfc4271

Installation
------------

.. tabs::

  .. group-tab:: Helm

        Cilium BGP Control Plane can be enabled with Helm flag ``bgpControlPlane.enabled``
        set as true.

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
                --namespace kube-system \\
                --reuse-values \\
                --set bgpControlPlane.enabled=true
            $ kubectl -n kube-system rollout restart ds/cilium

  .. group-tab:: Cilium CLI

        .. include:: ../../installation/cli-download.rst

        Cilium BGP Control Plane can be enabled with the following command

        .. parsed-literal::

            $ cilium install |CHART_VERSION| --set bgpControlPlane.enabled=true

IPv4/IPv6 single-stack and dual-stack setup are supported. Note that the BGP
Control Plane can only advertise the route of the address family that the
Cilium is configured to use. You cannot advertise IPv4 routes when the Cilium
Agent is configured to use only IPv6 address family. Conversely, you cannot advertise
IPv6 routes when Cilium Agent is configured to use only IPv4 address family.

Configuring BGP Control Plane
-----------------------------

There are two ways to configure the BGP Control Plane. Using legacy ``CiliumBGPPeeringPolicy`` resource,
or using newer BGP resources like ``CiliumBGPClusterConfig``. Currently, both configuration options are
supported, however ``CiliumBGPPeeringPolicy`` will be deprecated in the future.

.. toctree::
    :maxdepth: 2
    :glob:

    bgp-control-plane-v2
    bgp-control-plane-v1

Troubleshooting and Operation Guide
-----------------------------------

.. toctree::
    :maxdepth: 2
    :glob:

    bgp-control-plane-troubleshooting
    bgp-control-plane-operation
.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io


.. _bgp_cplane_contributing:

=================
BGP Control Plane
=================

This section is specific to :ref:`bgp_control_plane` contributions.

Development Environment
=======================

BGP Control Plane requires a BGP peer for testing. This section describes a `ContainerLab`_ and `Kind`_-based development environment. The following diagram shows the topology:

.. _ContainerLab: https://containerlab.dev/
.. _Kind: https://kind.sigs.k8s.io/

.. image:: _static/bgp-lab.drawio.png
    :align: center

The following describes the role of each node:

* ``router0`` is an `FRRouting (FRR)`_ router. It is pre-configured with minimal peering settings with server0 and server1.
* ``server0`` and ``server1`` are ``nicolaka/netshoot`` containers that each share a network namespace with their own Kind node.
* ``server2`` is a non-Cilium ``nicolaka/netshoot`` node useful for testing traffic connectivity from outside of the k8s cluster.

.. _FRRouting (FRR): https://frrouting.org/

Prerequisites
-------------

* ContainerLab v0.45.1 or later
* Kind v0.20.0 or later
* Your container runtime networks must not use ``10.0.0.0/8`` and ``fd00::/16``

Deploy Lab
----------

The following example deploys a lab with the latest stable version of Cilium:

.. code-block:: shell-session

   $ make kind-bgp-service

.. note::
        The prior example sets up an environment showcasing k8s service advertisements over BGP. Please refer to container lab directory in Cilium repository under ``contrib/containerlab`` for more labs.

If you want to install a locally built version of Cilium instead of the stable version, pass ``local`` as the ``VERSION`` environment variable value:

.. code-block:: shell-session

   $ make VERSION=local kind-bgp-service

Peering with Router
-------------------

Peer Cilium nodes with FRR by applying BGP configuration resources:

.. code-block:: shell-session

   $ make kind-bgp-service-apply-bgp

To deploy some example k8s services, run the following commands:

.. code-block:: shell-session

   $ make kind-bgp-service-apply-service

Validating Peering Status
-------------------------

You can validate the peering status with the following command. Confirm that
the session state is established and Received and Advertised counters are non-zero.

.. code-block:: shell-session

   $ cilium bgp peers
   Node                                   Local AS   Peer AS   Peer Address   Session State   Uptime   Family         Received   Advertised
   bgp-cplane-dev-service-control-plane   65001      65000     fd00:10::1     established     51s      ipv4/unicast   6          4
                                                                                                       ipv6/unicast   4          3
   bgp-cplane-dev-service-worker          65001      65000     fd00:10::1     established     51s      ipv4/unicast   6          6
                                                                                                       ipv6/unicast   4          4

Destroy Lab
-----------

.. code-block:: shell-session

   $ make kind-bgp-service-down

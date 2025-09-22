.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bgp_control_plane_troubeshooting:

BGP Control Plane Troubleshooting Guide
=======================================

This document enumerates typical troubles and their solutions when configuring the BGP
Control Plane.

Even though Cilium BGP resources are applied, BGP peering is not established
----------------------------------------------------------------------------

Check that the ``CiliumBGPNodeConfig`` resource is created for a given Node. If
``CiliumBGPNodeConfig`` resource is missing, check the Cilium operator logs for
any errors.

Check ``nodeSelector`` configuration and
peering configuration if the BGP state is not ``established``.

Another possibility is that the ``nodeSelector`` in the
``CiliumBGPClusterConfig`` doesn't match any nodes due to the missing labels or
misconfigured selector. In this case, the following status condition will be
set:

.. code:: yaml

  status:
    conditions:
    - lastTransitionTime: "2024-10-26T06:15:44Z"
      message: No node matches spec.nodeSelector
      observedGeneration: 2
      reason: NoMatchingNode
      status: "True"
      type: cilium.io/NoMatchingNode

Node is selected by CiliumBGPClusterConfig, but BGP peer is not established
---------------------------------------------------------------------------

You can identify the cause by referring to the logs of your peer router
or Cilium. The errors logged by the BGP Control Plane have a field
named ``subsys=bgp-control-plane``, which can be used to filter
logs for errors specific to BGP Control Plane:

.. code:: bash

   $ kubectl -n <your namespace> <cilium pod running on the target node> logs | grep bgp-control-plane
   ...
   level=warning msg="sent notification" Data="as number mismatch expected 65003, received 65000" Key=10.0.1.1 Topic=Peer asn=65001 component=gobgp.BgpServerInstance subsys=bgp-control-plane

In the example above, it can be seen that the BGP session was not
established because there was a mismatch between the configured
``peerASN`` and the actual ASN of the peer.

There could be various reasons why BGP peering is not established, such as a
mismatch in BGP capability or an incorrect Peer IP address. BGP layer errors
are likely to appear in the logs, but there are cases where low-level errors,
such as lack of connectivity to the Peer IP or when an eBGP peer is more than 1
hop away, may not be reflected in the logs. In such cases, using tools like
``WireShark`` or ``tcpdump`` can be effective.

Additional new CiliumBGPClusterConfig is not working
----------------------------------------------------

Multiple ``CiliumBGPClusterConfig`` resources
can not select the same node based on the ``nodeSelector`` field. If this is the case,
the Cilium operator will reject any additional ``CiliumBGPClusterConfig`` from creating
the ``CiliumBGPNodeConfig`` resource. Following status condition will be set on the
``CiliumBGPClusterConfig`` to indicate this:

.. code:: yaml

  status:
    conditions:
    - lastTransitionTime: "2024-10-26T06:18:04Z"
      message: 'Selecting the same node(s) with ClusterConfig(s): [cilium-bgp-0]'
      observedGeneration: 1
      reason: ConflictingClusterConfigs
      status: "True"
      type: cilium.io/ConflictingClusterConfig

CiliumBGPPeerConfig doesn't take effect
---------------------------------------

If the ``CiliumBGPPeerConfig`` is not taking effect, it may be because there is a
misconfiguration (such as typo) in the ``peerConfigRef`` and the reference is not
effective. Following status condition will be set if the referenced ``CiliumBGPPeerConfig``
is not found:

.. code:: yaml

  status:
    conditions:
    - lastTransitionTime: "2024-10-26T06:15:44Z"
      message: 'Referenced CiliumBGPPeerConfig(s) are missing: [peer-cofnig0]'
      observedGeneration: 1
      reason: MissingPeerConfigs
      status: "True"
      type: cilium.io/MissingPeerConfigs

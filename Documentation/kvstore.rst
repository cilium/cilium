Key-Value Store
###############

Cilium uses an external key-value store to exchange information across multiple
Cilium instances:

Layout
======

All data is stored under a common key prefix:

===================== ====================
Prefix                Description
===================== ====================
``cilium/``           All keys share this common prefix.
``cilium/state/``     State stored by agents, data is automatically recreated on removal or corruption.
===================== ====================


Cluster Nodes
-------------

Every agent will register itself as a node in the kvstore and make the
following information available to other agents:

- Name
- IP addresses of the node
- Health checking IP addresses
- Allocation range of endpoints on the node

============================================================ ====================
Key                                                          Value
============================================================ ====================
``cilium/state/nodes/v1/<cluster>/<node>``                   node.Node_
============================================================ ====================

.. _node.Node: https://godoc.org/github.com/cilium/cilium/pkg/node#Node

All node keys are attached to a lease owned by the agent of the respective
node.


Services
--------

All Kubernetes services are mirrored into the kvstore by the Cilium operator. This is
required to implement multi cluster service discovery.

============================================================= ====================
Key                                                           Value
============================================================= ====================
``cilium/state/services/v1/<cluster>/<namespace>/<service>``  service.ClusterService_
============================================================= ====================

.. _service.ClusterService: https://godoc.org/github.com/cilium/cilium/pkg/service#ClusterService

Identities
----------

Any time a new endpoint is started on a Cilium node, it will determine whether
the labels for the endpoint are unique and allocate an identity for that set of
labels. These identities are only meaningful within the local cluster.

============================================================= ====================
Key                                                           Value
============================================================= ====================
``cilium/state/identities/v1/id/<identity>``                  labels.LabelArray_
``cilium/state/identities/v1/value/<labels>/<node>``          identity.NumericIdentity_
============================================================= ====================

.. _identity.NumericIdentity: https://godoc.org/github.com/cilium/cilium/pkg/identity#NumericIdentity
.. _labels.LabelArray: https://godoc.org/github.com/cilium/cilium/pkg/labels#LabelArray

Endpoints
---------

All endpoint IPs and corresponding identities are mirrored to the kvstore by
the agent on the node where the endpoint is launched, to allow peer nodes to
configure egress policies to endpoints backed by these IPs.

============================================================= ====================
Key                                                           Value
============================================================= ====================
``cilium/state/ip/v1/<cluster>/<ip>``                         identity.IPIdentityPair_
============================================================= ====================

.. _identity.IPIdentityPair: https://godoc.org/github.com/cilium/cilium/pkg/identity#IPIdentityPair

Leases
======

With a few exceptions, all keys in the key-value store are owned by a
particular agent running on a node. All such keys have a lease attached. The
lease is renewed automatically. When the lease expires, the key is removed from
the key-value store. This guarantees that keys are removed from the key-value
store in the event that an agent dies on a particular and never reappears.

The lease lifetime is set to 15 minutes. The exact expiration behavior is
dependent on the kvstore implementation but the expiration typically occurs
after double the lifetime

Debugging
=========

The contents stored in the kvstore can be queued and manipulate using the
``cilium kvstore`` command. For additional details, see the command reference.

Example:

.. code:: bash

        $ cilium kvstore get --recursive cilium/state/nodes/
        cilium/state/nodes/v1/default/runtime1 => {"Name":"runtime1","IPAddresses":[{"AddressType":"InternalIP","IP":"10.0.2.15"}],"IPv4AllocCIDR":{"IP":"10.11.0.0","Mask":"//8AAA=="},"IPv6AllocCIDR":{"IP":"f00d::a0f:0:0:0","Mask":"//////////////////8AAA=="},"IPv4HealthIP":"","IPv6HealthIP":""}

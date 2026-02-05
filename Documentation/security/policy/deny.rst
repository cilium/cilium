.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _deny_policies:

Deny Policies
=============

Deny policies, available and enabled by default since Cilium 1.9, allows to
explicitly restrict certain traffic to and from a Pod.

Deny policies take precedence over allow policies, regardless of whether they
are a Cilium Network Policy, a Clusterwide Cilium Network Policy or even a
Kubernetes Network Policy.

Similarly to "allow" policies, Pods will enter default-deny mode as soon a
single policy selects it.

If multiple allow and deny policies are applied to the same pod, the following
table represents the expected enforcement for that Pod:

+--------------------------------------------------------------------------------------------+
| **Set of Ingress Policies Deployed to Server Pod**                                         |
+---------------------+-----------------------+---------+---------+--------+--------+--------+
|                     | Layer 7 (HTTP)        | ✓       | ✓       | ✓      | ✓      |        |
|                     +-----------------------+---------+---------+--------+--------+--------+
|                     | Layer 4 (80/TCP)      | ✓       | ✓       | ✓      | ✓      |        |
| **Allow Policies**  +-----------------------+---------+---------+--------+--------+--------+
|                     | Layer 4 (81/TCP)      | ✓       | ✓       | ✓      | ✓      |        |
|                     +-----------------------+---------+---------+--------+--------+--------+
|                     | Layer 3 (Pod: Client) | ✓       | ✓       | ✓      | ✓      |        |
+---------------------+-----------------------+---------+---------+--------+--------+--------+
|                     | Layer 4 (80/TCP)      |         | ✓       |        | ✓      | ✓      |
| **Deny Policies**   +-----------------------+---------+---------+--------+--------+--------+
|                     | Layer 3 (Pod: Client) |         |         | ✓      | ✓      |        |
+---------------------+-----------------------+---------+---------+--------+--------+--------+
| **Result for Traffic Connections (Allowed / Denied)**                                      |
+---------------------+-----------------------+---------+---------+--------+--------+--------+
|                     | curl server:81        | Allowed | Allowed | Denied | Denied | Denied |
|                     +-----------------------+---------+---------+--------+--------+--------+
| **Client → Server** | curl server:80        | Allowed | Denied  | Denied | Denied | Denied |
|                     +-----------------------+---------+---------+--------+--------+--------+
|                     | ping server           | Allowed | Allowed | Denied | Denied | Denied |
+---------------------+-----------------------+---------+---------+--------+--------+--------+

If we pick the second column in the above table, the bottom section shows the
forwarding behaviour for a policy that selects curl or ping traffic between the
client and server:

* Curl to port 81 is allowed because there is an allow policy on port 81, and
  no deny policy on that port;
* Curl to port 80 is denied because there is a deny policy on that port;
* Ping to the server is allowed because there is a Layer 3 allow policy and no deny.

The following policy will deny ingress from "world" on all namespaces on all
Pods managed by Cilium. Existing inter-cluster policies will still be allowed
as this policy is allowing traffic from everywhere except from "world".

.. literalinclude:: ../../../examples/policies/l3/entities/from_world_deny.yaml
  :language: yaml

Deny policies do not support: policy enforcement at L7, i.e., specifically
denying an URL and ``toFQDNs``, i.e., specifically denying traffic to a specific
domain name.

.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _network_policy:
.. _Network Policies:
.. _Network Policy:

Network Policy
==============

This chapter documents the policy language used to configure network policies
in Cilium. Security policies can be specified and imported via the following
mechanisms:

* Using Kubernetes `NetworkPolicy`, `CiliumNetworkPolicy` and `CiliumClusterwideNetworkPolicy`
  resources. See the section :ref:`k8s_policy` for more details. In this mode,
  Kubernetes will automatically distribute the policies to all agents.

* Directly imported into the agent via CLI or :ref:`api_ref` of the agent. This
  method does not automatically distribute policies to all agents. It is in the
  responsibility of the user to import the policy in all required agents.

.. toctree::
   :maxdepth: 1
   :glob:

   intro
   language
   visibility
   kubernetes
   lifecycle
   troubleshooting
   caveats

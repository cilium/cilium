.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _network_policy:
.. _Network Policies:
.. _Network Policy:

Overview of Network Policy
--------------------------

This chapter documents the policy language used to configure network policies
in Cilium. For a basic understanding, read the :ref:`introduction <policy_guide>`.
More details are covered on the respective pages for different kinds of policies
and ways to define them.

Security policies can be specified and imported via the following mechanisms:

* Using Kubernetes `NetworkPolicy`, `CiliumNetworkPolicy` and `CiliumClusterwideNetworkPolicy`
  resources. See the section :ref:`k8s_policy` for more details. In this mode,
  Kubernetes will automatically distribute the policies to all agents.

* Directly imported into the agent via CLI or :ref:`api_ref` of the agent. This
  method does not automatically distribute policies to all agents. It is in the
  responsibility of the user to import the policy in all required agents. (This
  method is deprecated as of v1.18 and will be removed in v1.19.)

.. toctree::
   :maxdepth: 2
   :glob:

   intro
   layer3
   layer4
   layer7
   deny
   disk-based
   host
   kubernetes
   lifecycle
   troubleshooting
   caveats

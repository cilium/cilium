.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _CiliumCIDRGroup:

***************************
CiliumCIDRGroup
***************************

CiliumCIDRGroup (CCG) is a feature that allows administrators to reference a group of
CIDR blocks in a :ref:`CiliumNetworkPolicy`. Unlike :ref:`CiliumEndpoint` resources,
which are managed by the Cilium agent, CiliumCIDRGroup resources are intended
to be managed directly by administrators.
It is particularly useful for enforcing policies on groups of external CIDR blocks. 
Additionally, any traffic to CIDRs referenced in the CiliumCIDRGroup will have their 
:ref:`Hubble <hubble_intro>` flows annotated with the CCG's name and labels.


The following is an example of a ``CiliumCIDRGroup`` object:


.. code-block:: yaml

  apiVersion: cilium.io/v2alpha1
  kind: CiliumCIDRGroup
  metadata:
    name: vpn-example-1
    labels:
      role: vpn 
  spec:
    externalCIDRs:
      - "10.48.0.0/24"
      - "10.16.0.0/24"


The CCG can be referenced in a ``CiliumNetworkPolicy``
by using the ``fromCIDRSet`` directive. CCGs may be selected
by names or labels.


.. code-block:: yaml

  apiVersion: cilium.io/v2
  kind: CiliumNetworkPolicy
  metadata:
    name: from-vpn-example
  spec:
    endpointSelector: {}
    ingress:
    ## select by name
    - fromCIDRSet:
      - cidrGroupRef: vpn-example-1
    ## alternatively, select by label:
    - fromCIDRSet:
      - cidrGroupSelector:
          matchLabels:
            role: vpn


In this example, the ``fromCIDRSet`` directive in the CNP references the
``vpn-example-1`` group defined in the ``CiliumCIDRGroup``. This allows the CNP to
apply ingress rules based on the CIDRs grouped under the ``vpn-example-1`` name.
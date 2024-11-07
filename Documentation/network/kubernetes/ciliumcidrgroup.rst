.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _CiliumCIDRGroup:

***************************
CiliumCIDRGroup
***************************

.. note::

    **Beta Feature:** CiliumCIDRGroup is currently in beta. We welcome your feedback
    and encourage you to report any issues by filing a GitHub issue.

    For the list of outstanding tasks and known issues, please refer to :gh-issue:`24801`.

CiliumCIDRGroup (CCG) is a feature that allows administrators to reference a group of
CIDR blocks in a :ref:`CiliumNetworkPolicy`. Unlike :ref:`CiliumEndpoint` resources,
which are managed by the Cilium agent, CiliumCIDRGroup resources are intended
to be managed directly by administrators.
It is particularly useful for enforcing policies on groups of external CIDR blocks.

The following is an example of a ``CiliumCIDRGroup`` object:


.. code-block:: yaml

  apiVersion: cilium.io/v2alpha1
  kind: CiliumCIDRGroup
  metadata:
    name: vpn
  spec:
    externalCIDRs:
      - "10.48.0.0/24"
      - "10.16.0.0/24"


The ``vpn`` CCG can be referenced in a ``CiliumNetworkPolicy``
by using the ``fromCIDRSet`` directive:


.. code-block:: yaml

  apiVersion: cilium.io/v2
  kind: CiliumNetworkPolicy
  metadata:
    name: from-vpn-example
  spec:
    endpointSelector: {}
    ingress:
    - fromCIDRSet:
      - cidrGroupRef: vpn


In this example, the ``fromCIDRSet`` directive in the CNP references the
``vpn`` group defined in the ``CiliumCIDRGroup``. This allows the CNP to
apply ingress rules based on the CIDRs grouped under the ``vpn`` name.

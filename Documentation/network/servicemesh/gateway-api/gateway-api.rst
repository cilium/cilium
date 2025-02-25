.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_api:

*******************
Gateway API Support
*******************

What is Gateway API?
####################

Gateway API is a Kubernetes SIG-Network subproject to design a successor for
the Ingress object. It is a set of resources that model service networking in
Kubernetes, and is designed to be role-oriented, portable, expressive, and
extensible.

See the `Gateway API site <https://gateway-api.sigs.k8s.io/>`__ for more details.

Cilium Gateway API Support
##########################

Cilium supports Gateway API v1.2.0 for below resources, all the Core conformance
tests are passed.

- `GatewayClass <https://gateway-api.sigs.k8s.io/api-types/gatewayclass/>`_
- `Gateway <https://gateway-api.sigs.k8s.io/api-types/gateway/>`_
- `HTTPRoute <https://gateway-api.sigs.k8s.io/api-types/httproute/>`_
- `GRPCRoute <https://gateway-api.sigs.k8s.io/api-types/grpcroute/>`__
- `TLSRoute (experimental) <https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io/v1alpha2.TLSRoute>`__
- `ReferenceGrant <https://gateway-api.sigs.k8s.io/api-types/referencegrant/>`_

Additionally, Cilium provides ``CiliumGatewayClassConfig`` CRD, which can be referenced in
`GatewayClass.parametersRef <https://gateway-api.sigs.k8s.io/api-types/gatewayclass/#gatewayclass-parameters>`_.

.. admonition:: Video
 :class: attention

  If you'd like more insights on Cilium's Gateway API support, check out `eCHO episode 58: Cilium Service Mesh and Ingress <https://www.youtube.com/watch?v=60epwCxO8G4&index=80&t=2024s>`__.

.. include:: installation.rst

.. include:: ../ingress-reference.rst

.. _gs_gateway_host_network_mode:
.. include:: host-network-mode.rst

.. _gs_gateway_addresses:
.. include:: addresses.rst

Examples
########

Please refer to one of the below examples on how to use and leverage
Cilium's Gateway API features:

.. toctree::
   :maxdepth: 1
   :glob:

   http
   https
   splitting
   header
   parameterized-gatewayclass

More examples can be found in the `upstream repository <https://github.com/kubernetes-sigs/gateway-api/tree/v1.2.0/examples/standard>`_.

Troubleshooting
###############

.. include:: troubleshooting.rst
.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_api:

*******************
Gateway API Support
*******************

Cilium supports Gateway API v0.6.1 for below resources, all the Core conformance
tests are passed.

- `GatewayClass <https://gateway-api.sigs.k8s.io/api-types/gatewayclass/>`_
- `Gateway <https://gateway-api.sigs.k8s.io/api-types/gateway/>`_
- `HTTPRoute <https://gateway-api.sigs.k8s.io/api-types/httproute/>`_
- `ReferenceGrant <https://gateway-api.sigs.k8s.io/api-types/referencegrant/>`_

.. include:: installation.rst

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

More examples can be found `upstream repository <https://github.com/kubernetes-sigs/gateway-api/tree/v0.6.1/examples/standard>`_.

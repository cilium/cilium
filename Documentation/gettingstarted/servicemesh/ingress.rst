.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_ingress:

**************************
Kubernetes Ingress Support
**************************

Cilium uses the standard Kubernetes Ingress resource definition, with
an ``ingressClassName`` of ``cilium``. This can be used for path-based
routing and for TLS termination.

.. Note::

    The ingress controller creates a service of LoadBalancer type, so
    your environment will need to support this

This is a step-by-step guide on how to enable the Ingress Controller in
an existing K8s cluster with Cilium installed.

.. include:: installation.rst

Examples
########

Please refer to one of the below examples on how to use and leverage
Cilium's Ingress features:

.. toctree::
   :maxdepth: 1
   :glob:

   http
   grpc
   tls-termination

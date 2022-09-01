.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

***************
Proxy Injection
***************

Cilium is capable of transparently injecting a Layer 4 proxy into any network
connection. This is used as the foundation to enforce higher level network
policies (see :ref:`DNS based` and :ref:`l7_policy`).

The following proxies can be injected:

.. toctree::
   :maxdepth: 1
   :glob:

   envoy


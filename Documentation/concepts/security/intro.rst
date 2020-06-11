.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

*****
Intro
*****

Cilium provides security on multiple levels. Each can be used individually or
combined together.

* :ref:`arch_id_security`: Connectivity policies between endpoints (Layer 3),
  e.g. any endpoint with label ``role=frontend`` can connect to any endpoint with
  label ``role=backend``.
* Restriction of accessible ports (Layer 4) for both incoming and outgoing
  connections, e.g. endpoint with label ``role=frontend`` can only make outgoing
  connections on port 443 (https) and endpoint ``role=backend`` can only accept
  connections on port 443 (https).
* Fine grained access control on application protocol level to secure HTTP and
  remote procedure call (RPC) protocols, e.g the endpoint with label
  ``role=frontend`` can only perform the REST API call ``GET /userdata/[0-9]+``,
  all other API interactions with ``role=backend`` are restricted.

Currently on the roadmap, to be added soon:

* Authentication: Any endpoint which wants to initiate a connection to an
  endpoint with the label ``role=backend`` must have a particular security
  certificate to authenticate itself before being able to initiate any
  connections. See `GH issue 502
  <https://github.com/cilium/cilium/issues/502>`_ for additional details.
* Encryption: Communication between any endpoint with the label ``role=frontend``
  to any endpoint with the label ``role=backend`` is automatically encrypted with
  a key that is automatically rotated. See `GH issue 504
  <https://github.com/cilium/cilium/issues/504>`_ to track progress on this
  feature.

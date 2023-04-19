.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

*****************************
Administrative API Enablement
*****************************

Cilium 1.14 introduced a new set of flags that you can use to selectively
enable which API endpoints are exposed to clients. When an API client makes a
request to an API endpoint that is administratively disabled, the server
responds with an HTTP 403 Forbidden error.

You can configure the option with a list of endpoints as described in the
following sections, or by specifying an option with the ``*`` suffix. If ``*``
is provided directly as a flag value, then all APIs are enabled. If there is
text before the ``*``, then the API flag must start with that prefix in order
for the flag to enable that option. For example, ``Get*`` enables all read-only
"GET" APIs without enabling any write APIs.

The cilium-agent relies on several of these APIs for its basic duties. In
particular, disabling the following APIs will likely cause significant
disruption to agent operations:

- ``GetConfig``
- ``GetHealthz``
- ``PutEndpointID``
- ``DeleteEndpointID``
- ``PostIPAM``
- ``DeleteIPAMIP``

The following sections outline the flags for different Cilium binaries and the
API endpoints that may be configured using those flags.

.. include:: api-restrictions-table.rst

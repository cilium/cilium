.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _api_ref:

#############
API Reference
#############

************
Introduction
************

The Cilium API is JSON based and provided by the ``cilium-agent``. The purpose
of the API is to provide visibility and control over an individual agent
instance. In general, all API calls affect only the resources managed by the
individual ``cilium-agent`` serving the API. A few selected API calls such as
the security identity resolution provides cluster wide visibility. Such API
calls are marked specifically. Unless noted otherwise, API calls will only affect
local agent resources.

*********************
How to access the API
*********************

CLI Client
==========

The easiest way to access the API is via the ``cilium`` CLI client. ``cilium``
will automatically locate the API of the agent running on the same node and
access it. However, using the ``-H`` or ``--host`` flag, the ``cilium`` client
can be pointed to an arbitrary API address.

Example
-------

.. code-block:: shell-session

    $ cilium -H unix:///var/run/cilium/cilium.sock
    [...]


Golang Package
==============

The following Go packages can be used to access the API:

+---------------------+---------------------------------------------------------------+
| Package             | Description                                                   |
+---------------------+---------------------------------------------------------------+
| `pkg/client`_       | Main client API abstraction                                   |
+---------------------+---------------------------------------------------------------+
| `api/v1/models`_    | API resource data type models                                 |
+---------------------+---------------------------------------------------------------+

Example
-------

The full example can be found in the `cilium/client-example`_ repository.

.. code-block:: go

    import (
            "fmt"

            "github.com/cilium/cilium/pkg/client"
    )

    func main() {
            c, err := client.NewDefaultClient()
            if err != nil {
                    ...
            }

            endpoints, err := c.EndpointList()
            if err != nil {
                    ...
            }

            for _, ep := range endpoints {
                    fmt.Printf("%8d %14s %16s %32s\n", ep.ID, ep.ContainerName, ep.Addressing.IPV4, ep.Addressing.IPV6)
            }

************************
Compatibility Guarantees
************************

Cilium API is stable as of version 1.0, backward compatibility will be upheld
for whole lifecycle of Cilium 1.x.

*************
API Reference
*************

.. openapi:: ../api/v1/openapi.yaml

.. _pkg/client: https://godoc.org/github.com/cilium/cilium/pkg/client
.. _api/v1/models: https://godoc.org/github.com/cilium/cilium/api/v1/models
.. _cilium/client-example: https://github.com/cilium/client-example

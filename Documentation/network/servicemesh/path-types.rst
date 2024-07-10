.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_ingress_path_types:

**************************
Ingress Path Types Example
**************************

This example walks through how various path types interact and allows you to
test that Cilium is working as it should.

This example requires that Cilium Ingress is enabled, and ``kubectl`` and ``jq``
must be installed.

Deploy the example app
======================

This deploys five copies of the ingress-conformance-echo tool, that will allow
us to see what paths are forwarded to what backends.

.. code-block:: shell-session

    $ # Apply the base definitions
    $ kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/examples/kubernetes/servicemesh/ingress-path-types.yaml
    $ # Apply the Ingress
    $ kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/examples/kubernetes/servicemesh/ingress-path-types-ingress.yaml


Review the Ingress
==================

Here is the Ingress used:

.. literalinclude:: ../../../examples/kubernetes/servicemesh/ingress-path-types-ingress.yaml

You can see here that there are five matches, one for each of our deployments.

The Ingress deliberately has the rules in a different order to what they will be
configured in Envoy.

* For Exact matches, we only match ``/exact`` and send that to the ``exactpath`` Service.
* For Prefix matches, we match ``/``, send that to the ``prefixpath`` Service,
  and match ``/prefix`` and send that to the ``prefixpath2`` Service.
* For ImplementationSpecific matches, we match ``/impl.+`` (a full regex), and
  send that to the ``implpath2`` Service. We also match ``/impl`` (without regex
  characters) and send that to the ``implpath`` Service.

The intent here is to allow us to tell which rule we have matched by consulting
the echoed response from the ingress-conformance-echo containers.

Check that the Ingress has provisioned correctly
================================================

Firstly, we need to check that the Ingress has been provisioned correctly.

.. code-block:: shell-session

    $ export PATHTYPE_IP=`k get ing multiple-path-types -o json | jq -r '.status.loadBalancer.ingress[0].ip'`
    $ curl -s -H "Host: pathtypes.example.com" http://$PATHTYPE_IP/ | jq
    {
    "path": "/",
    "host": "pathtypes.example.com",
    "method": "GET",
    "proto": "HTTP/1.1",
    "headers": {
        "Accept": [
        "*/*"
        ],
        "User-Agent": [
        "curl/7.81.0"
        ],
        "X-Envoy-External-Address": [
        "your-ip-here"
        ],
        "X-Forwarded-For": [
        "your-ip-here"
        ],
        "X-Forwarded-Proto": [
        "http"
        ],
        "X-Request-Id": [
        "6bb145e8-addb-4fd5-a76f-b53d07bd1867"
        ]
    },
    "namespace": "default",
    "ingress": "",
    "service": "",
    "pod": "prefixpath-7cb697f5cd-wvv7b"
    }

Here you can see that the Ingress has been provisioned correctly and is responding
to requests. Also, you can see that the ``/`` path has been served by the
``prefixpath`` deployment, which is as expected from the Ingress.

Check that paths perform as expected
====================================

The following example uses ``jq`` to extract the first element out of the ``pod``
field, which is the name of the associated deployment. So, ``prefixpath-7cb697f5cd-wvv7b``
will return ``prefixpath``.

.. code-block:: shell-session

    $ echo Should show "prefixpath"
    Should show prefixpath
    $ curl -s -H "Host: pathtypes.example.com" http://$PATHTYPE_IP/ | jq '.pod | split("-")[0]'
    "prefixpath"
    $ echo Should show "exactpath"
    Should show exactpath
    $ curl -s -H "Host: pathtypes.example.com" http://$PATHTYPE_IP/exact | jq '.pod | split("-")[0]'
    "exactpath"
    $ echo Should show "prefixpath2"
    Should show prefixpath2
    $ curl -s -H "Host: pathtypes.example.com" http://$PATHTYPE_IP/prefix | jq '.pod | split("-")[0]'
    "prefixpath2"
    $ echo Should show "implpath"
    Should show implpath
    $ curl -s -H "Host: pathtypes.example.com" http://$PATHTYPE_IP/impl | jq '.pod | split("-")[0]'
    "implpath"
    $ echo Should show "implpath2"
    Should show implpath2
    $ curl -s -H "Host: pathtypes.example.com" http://$PATHTYPE_IP/implementation | jq '.pod | split("-")[0]'
    "implpath2"

(You can use the "Copy Commands" button above to do less copy-and-paste.)

The most interesting example here is the last one, where we send ``/implementation``
to the ``implpath2`` Service, while ``/impl`` goes to ``implpath``. This is because
``/implementation`` matches the ``/impl.+`` regex, and ``/impl`` matches the
``/impl`` regex.

If we now patch the Ingress object to use the regex ``/impl.*`` instead (note the
``*``, which matches **zero or more** characters of the type instead of the
previous ``+``, which matches **one or more** characters), then we will get a
different result for the last two checks:

.. code-block:: shell-session

    $ echo Should show "implpath2"
    Should show implpath
    $ curl -s -H "Host: pathtypes.example.com" http://$PATHTYPE_IP/impl | jq '.pod | split("-")[0]'
    "implpath"
    $ echo Should show "implpath2"
    Should show implpath2
    $ curl -s -H "Host: pathtypes.example.com" http://$PATHTYPE_IP/implementation | jq '.pod | split("-")[0]'
    "implpath2"

The request to ``/impl`` now matches the **longer** pattern ``/impl.*``.

The moral here is to be careful with your regular expressions!

Clean up the example
====================

Finally, we clean up our example:

.. code-block:: shell-session

    $ # Apply the base definitions
    $ kubectl delete -f https://raw.githubusercontent.com/cilium/cilium/examples/kubernetes/servicemesh/ingress-path-types.yaml
    $ # Apply the Ingress
    $ kubectl delete -f https://raw.githubusercontent.com/cilium/cilium/examples/kubernetes/servicemesh/ingress-path-types-ingress.yaml

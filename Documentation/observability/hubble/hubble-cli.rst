.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _hubble_cli:

*************************************
Inspecting Network Flows with the CLI
*************************************

This guide walks you through using the Hubble CLI to inspect network flows and
gain visibility into what is happening on the network level.

The best way to get help if you get stuck is to ask a question on `Cilium
Slack`_. With Cilium contributors across the globe, there is almost always
someone available to help.

.. note::

    This guide uses examples based on the Demo App. If you would like to run them,
    deploy the Demo App first. Please refer to :ref:`gs_http` for more details.

Pre-Requisites
==============

* Cilium has been correctly :ref:`installed in your Kubernetes cluster<k8s_quick_install>`.
* :ref:`Hubble is enabled<hubble_setup>`.
* :ref:`Hubble CLI is installed<hubble_cli_install>`.
* :ref:`The Hubble API is accessible<hubble_validate_api_access>`.

If unsure, run ``cilium status`` and validate that Cilium and Hubble are up and
running then run ``hubble status`` to verify you can communicate with the
Hubble API .

Inspecting the cluster's network traffic with Hubble Relay
==========================================================

Let's issue some requests to emulate some traffic again. This first request is
allowed by the policy.

.. code-block:: shell-session

    kubectl exec tiefighter -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
    Ship landed

This next request is accessing an HTTP endpoint which is denied by policy.

.. code-block:: shell-session

    kubectl exec tiefighter -- curl -s -XPUT deathstar.default.svc.cluster.local/v1/exhaust-port
    Access denied

Finally, this last request will hang because the ``xwing`` pod does not have
the ``org=empire`` label required by policy. Press Control-C to kill the curl
request, or wait for it to time out.

.. code-block:: shell-session

    kubectl exec xwing -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
    command terminated with exit code 28

Let's now inspect this traffic using the CLI. The command below filters all
traffic on the application layer (L7, HTTP) to the ``deathstar`` pod:

.. code-block:: shell-session

    hubble observe --pod deathstar --protocol http
    May  4 13:23:40.501: default/tiefighter:42690 -> default/deathstar-c74d84667-cx5kp:80 http-request FORWARDED (HTTP/1.1 POST http://deathstar.default.svc.cluster.local/v1/request-landing)
    May  4 13:23:40.502: default/tiefighter:42690 <- default/deathstar-c74d84667-cx5kp:80 http-response FORWARDED (HTTP/1.1 200 0ms (POST http://deathstar.default.svc.cluster.local/v1/request-landing))
    May  4 13:23:43.791: default/tiefighter:42742 -> default/deathstar-c74d84667-cx5kp:80 http-request DROPPED (HTTP/1.1 PUT http://deathstar.default.svc.cluster.local/v1/exhaust-port)



The following command shows all traffic to the ``deathstar`` pod that has been
dropped:

.. code-block:: shell-session

    hubble observe --pod deathstar --verdict DROPPED
    May  4 13:23:43.791: default/tiefighter:42742 -> default/deathstar-c74d84667-cx5kp:80 http-request DROPPED (HTTP/1.1 PUT http://deathstar.default.svc.cluster.local/v1/exhaust-port)
    May  4 13:23:47.852: default/xwing:42818 <> default/deathstar-c74d84667-cx5kp:80 Policy denied DROPPED (TCP Flags: SYN)
    May  4 13:23:47.852: default/xwing:42818 <> default/deathstar-c74d84667-cx5kp:80 Policy denied DROPPED (TCP Flags: SYN)
    May  4 13:23:48.854: default/xwing:42818 <> default/deathstar-c74d84667-cx5kp:80 Policy denied DROPPED (TCP Flags: SYN)

Feel free to further inspect the traffic. To get help for the ``observe``
command, use ``hubble help observe``.

Next Steps
==========

* :ref:`hubble_api_tls`

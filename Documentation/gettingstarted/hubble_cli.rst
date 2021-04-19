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

The best way to get help if you get stuck is to ask a question on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_.  With Cilium contributors
across the globe, there is almost always someone available to help.

.. tip::

   This guide assumes that Cilium has been correctly installed in your
   Kubernetes cluster and that Hubble has been enabled. Please see
   :ref:`k8s_quick_install` and :ref:`hubble_setup` for more information. If
   unsure, run ``cilium status`` and validate that Cilium and Hubble are up and
   running.


Generate some network traffic
=============================

In order to generate some network traffic, run the connectivity test:

.. code-block:: shell-session

   while true; do cilium connectivity test; done 

Inspecting the cluster's network traffic with Hubble Relay
==========================================================

In order to avoid passing ``--server`` argument to every command, you may
export the following environment variable:

.. code-block:: shell-session

   export HUBBLE_SERVER=localhost:4245

Let's now issue some requests to emulate some traffic again. This first request
is allowed by the policy.

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
    TIMESTAMP             SOURCE                                  DESTINATION                             TYPE            VERDICT     SUMMARY
    Jun 18 13:52:23.843   default/tiefighter:52568                default/deathstar-5b7489bc84-8wvng:80   http-request    FORWARDED   HTTP/1.1 POST http://deathstar.default.svc.cluster.local/v1/request-landing
    Jun 18 13:52:23.844   default/deathstar-5b7489bc84-8wvng:80   default/tiefighter:52568                http-response   FORWARDED   HTTP/1.1 200 0ms (POST http://deathstar.default.svc.cluster.local/v1/request-landing)
    Jun 18 13:52:31.019   default/tiefighter:52628                default/deathstar-5b7489bc84-8wvng:80   http-request    DROPPED     HTTP/1.1 PUT http://deathstar.default.svc.cluster.local/v1/exhaust-port


The following command shows all traffic to the ``deathstar`` pod that has been
dropped:

.. code-block:: shell-session

    hubble observe --pod deathstar --verdict DROPPED
    TIMESTAMP             SOURCE                     DESTINATION                             TYPE            VERDICT   SUMMARY
    Jun 18 13:52:31.019   default/tiefighter:52628   default/deathstar-5b7489bc84-8wvng:80   http-request    DROPPED   HTTP/1.1 PUT http://deathstar.default.svc.cluster.local/v1/exhaust-port
    Jun 18 13:52:38.321   default/xwing:34138        default/deathstar-5b7489bc84-v4s7d:80   Policy denied   DROPPED   TCP Flags: SYN
    Jun 18 13:52:38.321   default/xwing:34138        default/deathstar-5b7489bc84-v4s7d:80   Policy denied   DROPPED   TCP Flags: SYN
    Jun 18 13:52:39.327   default/xwing:34138        default/deathstar-5b7489bc84-v4s7d:80   Policy denied   DROPPED   TCP Flags: SYN

Feel free to further inspect the traffic. To get help for the ``observe``
command, use ``hubble help observe``.

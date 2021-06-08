.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _hubble_gsg:
.. _hubble_ui:

***********************
Service Map & Hubble UI
***********************

This tutorial guides you through enabling the Hubble UI to access the graphical
service map.

.. image:: images/hubble_sw_service_map.png

.. note::

   This guide assumes that Cilium has been correctly installed in your
   Kubernetes cluster and that Hubble has been enabled. Please see
   :ref:`k8s_quick_install` and :ref:`hubble_setup` for more information. If
   unsure, run ``cilium status`` and validate that Cilium and Hubble are up and
   running.

Enable the Hubble UI
====================

If you have not done so already, enable the Hubble UI by running the following command:

.. tabs::

    .. group-tab:: Cilium CLI 

        .. code-block:: shell-session

            cilium hubble enable --ui
            🔑 Found existing CA in secret cilium-ca
            ✨ Patching ConfigMap cilium-config to enable Hubble...
            ♻️  Restarted Cilium pods
            ✅ Relay is already deployed
            ✅ Hubble UI is already deployed

    .. group-tab:: Helm

        .. parsed-literal::

           helm upgrade cilium |CHART_RELEASE| \\
              --namespace $CILIUM_NAMESPACE \\
              --reuse-values \\
              --set hubble.relay.enabled=true \\
              --set hubble.ui.enabled=true


Open the Hubble UI
==================

Open the Hubble UI in your browser by running ``cilium hubble ui``. It will
automatically set up a port forward to the hubble-ui service in your Kubernetes
cluster and make it available on a local port on your machine.

.. code-block:: shell-session

    cilium hubble ui
    Forwarding from 0.0.0.0:12000 -> 8081
    Forwarding from [::]:12000 -> 8081

.. tip::

   The above command will block and continue running while the port forward is
   active. You can interrupt the command to abort the port forward and re-run
   the command to make the UI accessible again.

If your browser has not automatically opened the UI, open the page
http://localhost:12000 in your browser. You should see a screen with an
invitation to select a namespace, use the namespace selector dropdown on the
left top corner to select a namespace:

.. image:: images/hubble_service_map_namespace_selector.png

In this example, we are deploying the Star Wars demo from the :ref:`gs_http`
guide. However you can apply the same techniques to observe application
connectivity dependencies in your own namespace, and clusters for
application of any type.

Once the deployment is ready, issue a request from both spaceships to emulate
some traffic.

.. code-block:: shell-session

    $ kubectl exec xwing -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
    Ship landed
    $ kubectl exec tiefighter -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
    Ship landed

These requests will then be displayed in the UI as service dependencies between
the different pods:

.. image:: images/hubble_sw_service_map.png

In the bottom of the interface, you may also inspect each recent Hubble flow
event in your current namespace individually.

.. note::
    If you enable :ref:`proxy_visibility` on your pods, the Hubble UI service
    map will display the HTTP endpoints which are being accessed by the requests.

Inspecting a wide variety of network traffic
============================================

In order to generate some network traffic, run the connectivity test in a loop:

.. code-block:: shell-session

   while true; do cilium connectivity test; done 

To see the traffic in Hubble, open http://localhost:12000/cilium-test in your
browser.

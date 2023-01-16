.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_envoy_load_balancing:

***************************************************
Proxy Load Balancing for Kubernetes Services (beta)
***************************************************

This guide explains how to configure Proxy Load Balancing for Kubernetes
services using Cilium, which is useful for use cases such as gRPC
load-balancing. Once enabled, the traffic to a Kubernetes service will be
redirected to a Cilium-managed Envoy proxy for load balancing. This feature
is independent of the :ref:`gs_ingress` feature.

.. include:: ../../beta.rst

Deploy Test Applications
========================

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/test-application-proxy-loadbalancing.yaml

The test workloads consist of:

- one client deployment ``client``
- one service ``echo-service`` with two backend pods.

View information about these pods:

.. code-block:: shell-session

    $ kubectl get pods --show-labels -o wide
    NAME                              READY   STATUS    RESTARTS   AGE    IP          NODE           NOMINATED NODE   READINESS GATES   LABELS
    client-7dccb64ff6-t5gc7         1/1     Running   0          39s   10.244.0.125   minikube   <none>           <none>            kind=client,name=client,pod-template-hash=7dccb64ff6
    echo-service-744b6dd45b-487tn   2/2     Running   0          39s   10.244.0.71    minikube   <none>           <none>            kind=echo,name=echo-service,other=echo,pod-template-hash=744b6dd45b
    echo-service-744b6dd45b-mdjc2   2/2     Running   0          39s   10.244.0.213   minikube   <none>           <none>            kind=echo,name=echo-service,other=echo,pod-template-hash=744b6dd45b

.. code-block:: shell-session

    $ CLIENT=$(kubectl get pods -l name=client -o jsonpath='{.items[0].metadata.name}')

Start Observing Traffic with Hubble
===================================

Enable Hubble in your cluster with the step mentioned in :ref:`hubble_setup`.

Start a second terminal, then enable hubble port forwarding and observe
traffic for the service ``echo-service``:

.. code-block:: shell-session

    $ kubectl -n kube-system port-forward deployment/hubble-relay 4245:4245 &
    $ hubble observe --service echo-service -f


You should be able to get a response from both of the backend services
individually from ``client``:

.. code-block:: shell-session

    $ kubectl exec -it $CLIENT -- curl -v echo-service:8080/

Notice that Hubble shows all the flows between the client pod and the backend pods
via ``echo-service`` service.

::

    Jan 16 04:28:10.690: default/client-7dccb64ff6-t5gc7 (ID:5152) <> default/echo-service:8080 (world) pre-xlate-fwd TRACED (TCP)
    Jan 16 04:28:10.690: default/echo-service:8080 (world) <> default/client-7dccb64ff6-t5gc7 (ID:5152) post-xlate-rev TRANSLATED (TCP)

Add Proxy Load Balancing Annotations to the Services
====================================================

Adding a Layer 7 policy introduces the Envoy proxy into the path for this traffic.

.. code-block:: shell-session

    $ kubectl annotate service echo-service service.cilium.io/lb-l7=enabled
    service/echo-service annotated

Make a request to a backend service and observe the traffic with Hubble again:

.. code-block:: shell-session

    $ kubectl exec -it $CLIENT -- curl -v echo-service:8080/

The request is now proxied through the Envoy proxy and then flows to the backend.

::

    Jan 16 04:32:27.737: default/client-7dccb64ff6-t5gc7:56462 (ID:5152) -> default/echo-service:8080 (world) to-proxy FORWARDED (TCP Flags: SYN)
    Jan 16 04:32:27.737: default/client-7dccb64ff6-t5gc7:56462 (ID:5152) <- default/echo-service:8080 (world) to-endpoint FORWARDED (TCP Flags: SYN, ACK)
    Jan 16 04:32:27.737: default/client-7dccb64ff6-t5gc7:56462 (ID:5152) -> default/echo-service:8080 (world) to-proxy FORWARDED (TCP Flags: ACK)
    Jan 16 04:32:27.737: default/client-7dccb64ff6-t5gc7:56462 (ID:5152) -> default/echo-service:8080 (world) to-proxy FORWARDED (TCP Flags: ACK, PSH)
    Jan 16 04:32:27.739: default/client-7dccb64ff6-t5gc7:56462 (ID:5152) <- default/echo-service:8080 (world) to-endpoint FORWARDED (TCP Flags: ACK, PSH)
    Jan 16 04:32:27.740: default/client-7dccb64ff6-t5gc7:56462 (ID:5152) -> default/echo-service:8080 (world) to-proxy FORWARDED (TCP Flags: ACK, FIN)
    Jan 16 04:32:27.740: default/client-7dccb64ff6-t5gc7:56462 (ID:5152) <- default/echo-service:8080 (world) to-endpoint FORWARDED (TCP Flags: ACK, FIN)
    Jan 16 04:32:27.740: default/client-7dccb64ff6-t5gc7:56462 (ID:5152) -> default/echo-service:8080 (world) to-proxy FORWARDED (TCP Flags: ACK)

Supported Annotations
=====================

.. list-table::
   :widths: 40 25 25 25
   :header-rows: 1

   * - Name
     - Description
     - Applicable Values
     - Default Value
   * - ``service.cilium.io/lb-l7``
     - Enable L7 Load balancing for kubernetes service.
     - ``envoy``, ``disabled``
     - Default to ``disabled``
   * - ``service.cilium.io/lb-l7-algorithm``
     - The LB algorithm to be used for services.
     - ``round_robin``, ``least_request``, ``random``
     - Defaults to Helm option ``loadBalancer.l7.algorithm`` value.

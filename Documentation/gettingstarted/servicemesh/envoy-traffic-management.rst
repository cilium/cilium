.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_envoy_traffic_management:

*****************************************
L7 Load Balancing and URL re-writing
*****************************************

Cilium Service Mesh defines a ``CiliumEnvoyConfig`` CRD which allows users
to set the configuration of the Envoy component built into Cilium agents.

This example sets up an Envoy listener which load balances requests
between two backend services.

Deploy Test Applications
========================

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/test-application.yaml

The test workloads consist of:

- two client deployments, ``client`` and ``client2``
- two services, ``echo-service-1`` and ``echo-service-2``

View information about these pods:

.. code-block:: shell-session

    $ kubectl get pods --show-labels -o wide
    NAME                              READY   STATUS    RESTARTS   AGE    IP          NODE           NOMINATED NODE   READINESS GATES   LABELS
    client-7568bc7f86-dlfqr           1/1     Running   0          100s   10.0.1.8    minikube-m02   <none>           <none>            kind=client,name=client,pod-template-hash=7568bc7f86
    client2-8b4c4fd75-xn25d           1/1     Running   0          100s   10.0.1.24   minikube-m02   <none>           <none>            kind=client,name=client2,other=client,pod-template-hash=8b4c4fd75
    echo-service-1-97748874-4sztx     2/2     Running   0          100s   10.0.1.86   minikube-m02   <none>           <none>            kind=echo,name=echo-service-1,other=echo,pod-template-hash=97748874
    echo-service-2-76c584c4bf-p4z4w   2/2     Running   0          100s   10.0.1.16   minikube-m02   <none>           <none>            kind=echo,name=echo-service-2,pod-template-hash=76c584c4bf

You can see that

- Only ``client2`` is labeled with ``other=client`` - we will use this
  in a ``CiliumNetworkPolicy`` definition later in this example.

Make an environment variable with the pod ID for ``client2``:

.. code-block:: shell-session

    $ export CLIENT2=$(kubectl get pods -l name=client2 -o jsonpath='{.items[0].metadata.name}')

We are going to use Envoy configuration to load-balance requests between
these two services ``echo-service-1`` and ``echo-service-2``.

Start Observing Traffic with Hubble
===================================

Enable Hubble in your cluster with the step mentioned in :ref:`hubble_setup`.

Start a second terminal, then enable hubble port forwarding and observe
traffic from the ``client2`` pod:

.. code-block:: shell-session

    $ kubectl -n kube-system port-forward deployment/hubble-relay 4245:4245 &
    $ hubble observe --from-pod $CLIENT2 -f


You should be able to get a response from both of the backend services
individually from ``client2``:

.. code-block:: shell-session

    $ kubectl exec -it $CLIENT2 -- curl -v echo-service-1:8080/
    $ kubectl exec -it $CLIENT2 -- curl -v echo-service-2:8080/


Notice that Hubble shows all the flows between these pods as being either
``to/from-stack``, ``to/from-overlay`` or ``to/from-endpoint`` - there is no
traffic marked as flowing to or from the proxy at this stage. (This assumes
you don't already have any Layer 7 policies in place affecting this traffic.)

Verify that you get a 404 error response if you curl to the non-existent URL
``/foo`` on these services:

.. code-block:: shell-session

    $ kubectl exec -it $CLIENT2 -- curl -v echo-service-1:8080/foo
    $ kubectl exec -it $CLIENT2 -- curl -v echo-service-2:8080/foo

Add Layer 7 Policy
==================

Adding a Layer 7 policy introduces the Envoy proxy into the path for this traffic.

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/client-egress-l7-http.yaml
    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/client-egress-only-dns.yaml


Make a request to a backend service (either will do):

.. code-block:: shell-session

    $ kubectl exec -it $CLIENT2 -- curl -v echo-service-1:8080/
    $ kubectl exec -it $CLIENT2 -- curl -v echo-service-2:8080/foo

Adding a Layer 7 policy enables Layer 7 visibility. Notice that the Hubble output
now includes flows ``to-proxy``, and also shows the HTTP protocol information at
level 7 (for example ``HTTP/1.1 GET http://echo-service-1:8080/``)

Test Layer 7 Policy Enforcement
===============================

The policy only permits GET requests to the ``/`` path, so you will see requests
to any other URL being dropped. For example, try:

.. code-block:: shell-session

    $ kubectl exec -it $CLIENT2 -- curl -v echo-service-1:8080/foo


The Hubble output will show the HTTP request being dropped, like this:

::

    Jul  7 08:40:15.076: default/client2-8b4c4fd75-6pgvl:58586 -> default/echo-service-1-97748874-n7758:8080 http-request DROPPED (HTTP/1.1 GET http://echo-service-1:8080/foo)

And the curl should show a ``403 Forbidden response``.

Add Envoy load-balancing and URL re-writing
===========================================

Apply the ``envoy-traffic-management-test.yaml`` file, which defines a ``CiliumClusterwideEnvoyConfig``.


.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/envoy-traffic-management-test.yaml

.. include:: warning.rst

This configuration listens for traffic intended for either of the two
``echo-`` services and:

- load-balances 50/50 between the two backend ``echo-`` services
- rewrites the path ``/foo`` to ``/``

A request to ``/foo`` should now succeed, because of the path re-writing:

.. code-block:: shell-session

    $ kubectl exec -it $CLIENT2 -- curl -v echo-service-1:8080/foo


But the network policy still prevents requests to any path that is not
rewritten to ``/``. For example, this request will result in a packet
being dropped and a 403 Forbidden response code:

.. code-block:: shell-session

    $ kubectl exec -it $CLIENT2 -- curl -v echo-service-1:8080/bar

    ### Output from hubble observe
    Jul  7 08:43:47.165: default/client2-8b4c4fd75-6pgvl:33376 -> default/echo-service-2-76c584c4bf-874dm:8080 http-request DROPPED (HTTP/1.1 GET http://echo-service-1:8080/bar)


Try making several requests to one backend service. You should see in
the Hubble output approximately half the time, they are handled by the
other backend.

Example:

::

    Jul  7 08:45:25.807: default/client2-8b4c4fd75-6pgvl:37388 -> kube-system/coredns-64897985d-8jhhn:53 L3-L4 REDIRECTED (UDP)
    Jul  7 08:45:25.807: default/client2-8b4c4fd75-6pgvl:37388 -> kube-system/coredns-64897985d-8jhhn:53 to-proxy FORWARDED (UDP)
    Jul  7 08:45:25.807: default/client2-8b4c4fd75-6pgvl:37388 -> kube-system/coredns-64897985d-8jhhn:53 dns-request FORWARDED (DNS Query echo-service-1.default.svc.cluster.local. AAAA)
    Jul  7 08:45:25.807: default/client2-8b4c4fd75-6pgvl:37388 -> kube-system/coredns-64897985d-8jhhn:53 dns-request FORWARDED (DNS Query echo-service-1.default.svc.cluster.local. A)
    Jul  7 08:45:25.808: default/client2-8b4c4fd75-6pgvl:57942 -> default/echo-service-1:8080 none REDIRECTED (TCP Flags: SYN)
    Jul  7 08:45:25.808: default/client2-8b4c4fd75-6pgvl:57942 -> default/echo-service-1:8080 to-proxy FORWARDED (TCP Flags: SYN)
    Jul  7 08:45:25.808: default/client2-8b4c4fd75-6pgvl:57942 -> default/echo-service-1:8080 to-proxy FORWARDED (TCP Flags: ACK)
    Jul  7 08:45:25.808: default/client2-8b4c4fd75-6pgvl:57942 -> default/echo-service-1:8080 to-proxy FORWARDED (TCP Flags: ACK, PSH)
    Jul  7 08:45:25.809: default/client2-8b4c4fd75-6pgvl:57942 -> default/echo-service-2-76c584c4bf-874dm:8080 L3-L4 REDIRECTED (TCP Flags: SYN)
    Jul  7 08:45:25.809: default/client2-8b4c4fd75-6pgvl:57942 -> default/echo-service-2-76c584c4bf-874dm:8080 to-endpoint FORWARDED (TCP Flags: SYN)
    Jul  7 08:45:25.809: default/client2-8b4c4fd75-6pgvl:57942 -> default/echo-service-2-76c584c4bf-874dm:8080 to-endpoint FORWARDED (TCP Flags: ACK)
    Jul  7 08:45:25.809: default/client2-8b4c4fd75-6pgvl:57942 -> default/echo-service-2-76c584c4bf-874dm:8080 to-endpoint FORWARDED (TCP Flags: ACK, PSH)
    Jul  7 08:45:25.809: default/client2-8b4c4fd75-6pgvl:57942 -> default/echo-service-2-76c584c4bf-874dm:8080 http-request FORWARDED (HTTP/1.1 GET http://echo-service-1:8080/)
    Jul  7 08:45:25.811: default/client2-8b4c4fd75-6pgvl:57942 -> default/echo-service-1:8080 to-proxy FORWARDED (TCP Flags: ACK, FIN)
    Jul  7 08:45:25.811: default/client2-8b4c4fd75-6pgvl:57942 -> default/echo-service-1:8080 to-proxy FORWARDED (TCP Flags: ACK)
    Jul  7 08:45:30.811: default/client2-8b4c4fd75-6pgvl:57942 -> default/echo-service-2-76c584c4bf-874dm:8080 to-endpoint FORWARDED (TCP Flags: ACK, FIN)

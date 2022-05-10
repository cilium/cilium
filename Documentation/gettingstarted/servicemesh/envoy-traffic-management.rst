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

You will need a Kubernetes cluster with at least two nodes for this example.
Please take a look at :ref:`gs_guide` for different installation options.

Run ``cilium connectivity test`` to deploy the test applications used for
L7 egress tests:

.. code-block:: shell-session

    $ cilium connectivity test --test egress-l7

The test workloads run in the namespace ``cilium-test`` and consist of:

- two client deployments, ``client`` and ``client2``
- two backend services, ``echo-other-node`` and ``echo-same-node``

View information about these pods:

.. code-block:: shell-session

    $ kubectl get pods -n cilium-test --show-labels -o wide
    NAME                               READY   STATUS    RESTARTS   AGE   IP             NODE           NOMINATED NODE   READINESS GATES   LABELS
    client-6488dcf5d4-jkht2            1/1     Running   0          85s   10.244.1.196   kind-worker2   <none>           <none>            kind=client,name=client,pod-template-hash=6488dcf5d4
    client2-6dd75b74c6-c65jt           1/1     Running   0          85s   10.244.1.235   kind-worker2   <none>           <none>            kind=client,name=client2,other=client,pod-template-hash=6dd75b74c6
    echo-other-node-697d5d69b7-phx2j   1/1     Running   0          85s   10.244.2.52    kind-worker    <none>           <none>            kind=echo,name=echo-other-node,pod-template-hash=697d5d69b7
    echo-same-node-7967996674-l82xz    1/1     Running   0          85s   10.244.1.102   kind-worker2   <none>           <none>            kind=echo,name=echo-same-node,other=echo,pod-template-hash=7967996674

You can see that

- Only ``client2`` is labeled with ``other=client`` - we will use this
  in a ``CiliumNetworkPolicy`` definition later in this example.
- The pods for ``client``, ``client2`` and ``echo-same-node`` run on one node,
  while ``echo-other-node`` is scheduled to another node.

Make an environment variable with the pod ID for ``client2``:

.. code-block:: shell-session

    $ export CLIENT2=$(kubectl get pods -l name=client2 -n cilium-test  -o jsonpath='{.items[0].metadata.name}')

We are going to use Envoy configuration to load-balance requests between
these two backend services ``echo-other-node`` and ``echo-same-node``.

Start Observing Traffic with Hubble
===================================

Start a second terminal, then enable hubble port forwarding and observe
traffic from the ``client2`` pod:

.. code-block:: shell-session

    $ cilium hubble port-forward &
    $ hubble observe --from-pod cilium-test/$CLIENT2 -f


You should be able to get a response from both of the backend services
individually from ``client2``:

.. code-block:: shell-session

    $ kubectl exec -it -n cilium-test $CLIENT2 -- curl -v echo-same-node:8080/
    $ kubectl exec -it -n cilium-test $CLIENT2 -- curl -v echo-other-node:8080/


Notice that Hubble shows all the flows between these pods as being either
``to/from-stack``, ``to/from-overlay`` or ``to/from-endpoint`` - there is no
traffic marked as flowing to or from the proxy at this stage. (This assumes
you don't already have any Layer 7 policies in place affecting this traffic.)

Verify that you get a 404 error response if you curl to the non-existent URL
``/foo`` on these services:

.. code-block:: shell-session

    $ kubectl exec -it -n cilium-test $CLIENT2 -- curl -v echo-same-node:8080/foo
    $ kubectl exec -it -n cilium-test $CLIENT2 -- curl -v echo-other-node:8080/foo

Add Layer 7 Policy
==================

Adding a Layer 7 policy introduces the Envoy proxy into the path for this traffic.

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/client-egress-l7-http.yaml
    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/client-egress-only-dns.yaml


Make a request to a backend service (either will do):

.. code-block:: shell-session

    $ kubectl exec -it -n cilium-test $CLIENT2 -- curl -v echo-same-node:8080/
    $ kubectl exec -it -n cilium-test $CLIENT2 -- curl -v echo-other-node:8080/foo

Adding a Layer 7 policy enables Layer 7 visibility. Notice that the Hubble output
now includes flows ``to-proxy``, and also shows the HTTP protocol information at
level 7 (for example ``HTTP/1.1 GET http://echo-same-node:8080/``)

Test Layer 7 Policy Enforcement
===============================

The policy only permits GET requests to the ``/`` path, so you will see requests
to any other URL being dropped. For example, try:

.. code-block:: shell-session

    $ kubectl exec -it -n cilium-test $CLIENT2 -- curl -v echo-same-node:8080/foo


The Hubble output will show the HTTP request being dropped, like this:

::

    May 11 06:33:55.210: cilium-test/client2-6dd75b74c6-c65jt:54244 -> cilium-test/echo-same-node-7967996674-l82xz:8080 http-request DROPPED (HTTP/1.1 GET http://echo-same-node:8080/foo)

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

    $ kubectl exec -it -n cilium-test $CLIENT2 -- curl -v echo-same-node:8080/foo


But the network policy still prevents requests to any path that is not
rewritten to ``/``. For example, this request will result in a packet
being dropped and a 403 Forbidden response code:

.. code-block:: shell-session

    $ kubectl exec -it -n cilium-test $CLIENT2 -- curl -v echo-same-node:8080/bar

    ### Output from hubble observe
    May 11 06:43:51.971: cilium-test/client2-6dd75b74c6-c65jt:54112 -> cilium-test/echo-other-node-697d5d69b7-phx2j:8080 http-request DROPPED (HTTP/1.1 GET http://echo-same-node:8080/bar)


Try making several requests to one backend service. You should see
in the Hubble output approximately half the time, they are handled by the other
backend.

Example:

::

    May 11 06:42:19.363: cilium-test/client2-6dd75b74c6-c65jt:51545 -> kube-system/coredns-f9fd979d6-7xb2m:53 L3-L4 REDIRECTED (UDP)
    May 11 06:42:19.363: cilium-test/client2-6dd75b74c6-c65jt:51545 -> kube-system/coredns-f9fd979d6-7xb2m:53 to-proxy FORWARDED (UDP)
    May 11 06:42:19.363: cilium-test/client2-6dd75b74c6-c65jt:51545 -> kube-system/coredns-f9fd979d6-7xb2m:53 dns-request FORWARDED (DNS Query echo-same-node.cilium-test.svc.cluster.local. AAAA)
    May 11 06:42:19.363: cilium-test/client2-6dd75b74c6-c65jt:51545 -> kube-system/coredns-f9fd979d6-7xb2m:53 dns-request FORWARDED (DNS Query echo-same-node.cilium-test.svc.cluster.local. A)
    May 11 06:42:19.365: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-same-node:8080 none REDIRECTED (TCP Flags: SYN)
    May 11 06:42:19.365: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-same-node:8080 to-proxy FORWARDED (TCP Flags: SYN)
    May 11 06:42:19.365: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-same-node:8080 to-proxy FORWARDED (TCP Flags: ACK)
    May 11 06:42:19.365: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-same-node:8080 to-proxy FORWARDED (TCP Flags: ACK, PSH)
    May 11 06:42:19.365: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-other-node-697d5d69b7-phx2j:8080 L3-L4 REDIRECTED (TCP Flags: SYN)
    May 11 06:42:19.365: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-other-node-697d5d69b7-phx2j:8080 to-overlay FORWARDED (TCP Flags: SYN)
    May 11 06:42:19.365: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-other-node-697d5d69b7-phx2j:8080 to-endpoint FORWARDED (TCP Flags: SYN)
    May 11 06:42:19.365: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-other-node-697d5d69b7-phx2j:8080 to-overlay FORWARDED (TCP Flags: ACK)
    May 11 06:42:19.365: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-other-node-697d5d69b7-phx2j:8080 to-endpoint FORWARDED (TCP Flags: ACK)
    May 11 06:42:19.366: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-other-node-697d5d69b7-phx2j:8080 to-overlay FORWARDED (TCP Flags: ACK, PSH)
    May 11 06:42:19.366: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-other-node-697d5d69b7-phx2j:8080 to-endpoint FORWARDED (TCP Flags: ACK, PSH)
    May 11 06:42:19.366: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-other-node-697d5d69b7-phx2j:8080 http-request FORWARDED (HTTP/1.1 GET http://echo-same-node:8080/)
    May 11 06:42:19.368: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-same-node:8080 to-proxy FORWARDED (TCP Flags: ACK, FIN)
    May 11 06:42:19.368: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-same-node:8080 to-proxy FORWARDED (TCP Flags: ACK)
    May 11 06:42:24.369: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-other-node-697d5d69b7-phx2j:8080 to-overlay FORWARDED (TCP Flags: ACK, FIN)
    May 11 06:42:24.369: cilium-test/client2-6dd75b74c6-c65jt:54110 -> cilium-test/echo-other-node-697d5d69b7-phx2j:8080 to-endpoint FORWARDED (TCP Flags: ACK, FIN)

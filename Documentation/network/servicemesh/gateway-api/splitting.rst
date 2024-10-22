.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_splitting:

*************************
Traffic Splitting Example
*************************

HTTP traffic splitting is the process of sending incoming traffic to multiple backend services, based on predefined weights or other criteria. 
The Cilium Gateway API includes built-in support for traffic splitting, allowing users to easily distribute incoming traffic across multiple backend services. 
This is very useful for canary testing or A/B scenarios.

This particular example uses the Gateway API to load balance incoming traffic to different backends, starting with the same weights before testing with a 99/1 weight distribution.

.. include:: ../echo-app.rst

Deploy the Cilium Gateway
=========================

You can find an example Gateway and HTTPRoute definition in ``splitting.yaml``:

.. literalinclude:: ../../../../examples/kubernetes/gateway/splitting.yaml

Notice the even 50/50 split between the two Services.

Deploy the Gateway and the HTTPRoute:

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/splitting.yaml

The preceding example creates a Gateway named ``cilium-gw`` that listens on port 80.
A single route is defined and includes two different ``backendRefs`` (``echo-1`` and ``echo-2``) and weights associated with them.

.. code-block:: shell-session

    $ kubectl get gateway cilium-gw
    NAME        CLASS    ADDRESS          PROGRAMMED   AGE
    cilium-gw   cilium   172.18.255.200                8s

.. Note::

    Some providers like EKS use a fully-qualified domain name rather than an IP address.

Even traffic split
==================

Now that the Gateway is ready, you can make HTTP requests to the services.

.. code-block:: shell-session

    $ GATEWAY=$(kubectl get gateway cilium-gw -o jsonpath='{.status.addresses[0].value}')
    $ curl --fail -s http://$GATEWAY/echo

    Hostname: echo-1-7d88f779b-m6r46

    Pod Information:
        node name:      kind-worker2
        pod name:       echo-1-7d88f779b-m6r46
        pod namespace:  default
        pod IP: 10.0.2.15

    Server values:
        server_version=nginx: 1.12.2 - lua: 10010

    Request Information:
        client_address=10.0.2.252
        method=GET
        real path=/echo
        query=
        request_version=1.1
        request_scheme=http
        request_uri=http://172.18.255.200:8080/echo

    Request Headers:
        accept=*/*  
        host=172.18.255.200  
        user-agent=curl/7.81.0  
        x-forwarded-proto=http  
        x-request-id=ee152a07-2be2-4539-b74d-ebcebf912907  

    Request Body:
        -no body in request-

Notice that the reply includes the name of the Pod that received the query. For example:

.. code-block:: shell-session

    Hostname: echo-2-5bfb6668b4-2rl4t

Repeat the command several times.
You should see the reply balanced evenly across both Pods and Nodes.
Verify that traffic is evenly split across multiple Pods by running a loop and counting the requests:

.. code-block:: shell-session

    while true; do curl -s -k "http://$GATEWAY/echo" >> curlresponses.txt ;done

Stop the loop with ``Ctrl+C``.
Verify that the responses are more or less evenly distributed.

.. code-block:: shell-session

    $ cat curlresponses.txt| grep -c "Hostname: echo-1"
    1221
    $ cat curlresponses.txt| grep -c "Hostname: echo-2"
    1162

Uneven (99/1) traffic split
===========================

Update the HTTPRoute weights, either by using ``kubectl edit httproute`` or by updating the value in the original manifest before reapplying it to. For example, set ``99`` for echo-1 and ``1`` for echo-2:

.. code-block:: shell-session

    backendRefs:
    - kind: Service
      name: echo-1
      port: 8080
      weight: 99
    - kind: Service
      name: echo-2
      port: 8090
      weight: 1


Verify that traffic is unevenly split across multiple Pods by running a loop and counting the requests:

.. code-block:: shell-session

    while true; do curl -s -k "http://$GATEWAY/echo" >> curlresponses991.txt ;done

Stop the loop with ``Ctrl+C``.
Verify that responses are more or less evenly distributed.

.. code-block:: shell-session

    $ cat curlresponses991.txt| grep -c "Hostname: echo-1"
    24739
    $ cat curlresponses991.txt| grep -c "Hostname: echo-2"
    239

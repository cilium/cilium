.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

***************************
Default Deny Ingress Policy
***************************

Let's apply a `CiliumClusterwideNetworkPolicy` to deny all traffic by default:

.. literalinclude:: ../../../examples/kubernetes/servicemesh/policy/default-deny.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/policy/default-deny.yaml

With this policy applied, the request to the ``/details`` endpoint will be denied for external and in-cluster traffic.

.. code-block:: shell-session

    $ curl --fail -v http://"$HTTP_INGRESS"/details/1
    *   Trying 172.19.255.194:80...
    * Connected to 172.19.255.194 (172.19.255.194) port 80
    > GET /details/1 HTTP/1.1
    > Host: 172.19.255.194
    > User-Agent: curl/8.6.0
    > Accept: */*
    >
    < HTTP/1.1 403 Forbidden
    < content-length: 15
    < content-type: text/plain
    < date: Sun, 17 Mar 2024 13:52:38 GMT
    < server: envoy
    * The requested URL returned error: 403
    * Closing connection
    curl: (22) The requested URL returned error: 403

    # Capture hubble flows in another terminal
    $ kubectl --namespace=kube-system exec -i -t cilium-xjl4x -- hubble observe -f --identity ingress
    Defaulted container "cilium-agent" out of: cilium-agent, config (init), mount-cgroup (init), apply-sysctl-overwrites (init), mount-bpf-fs (init), wait-for-node-init (init), clean-cilium-state (init), install-cni-binaries (init)
    Mar 17 13:56:00.709: 172.19.0.1:34104 (ingress) -> default/cilium-ingress-basic-ingress:80 (world) http-request DROPPED (HTTP/1.1 GET http://172.19.255.194/details/1)
    Mar 17 13:56:00.709: 172.19.0.1:34104 (ingress) <- default/cilium-ingress-basic-ingress:80 (world) http-response FORWARDED (HTTP/1.1 403 0ms (GET http://172.19.255.194/details/1))

Now let's check if in-cluster traffic to the same endpoint is denied:

.. parsed-literal::

    # The test-application.yaml contains a client pod with curl available
    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/test-application.yaml
    $ kubectl exec -it deployment/client -- curl -s http://$HTTP_INGRESS/details/1
    Access denied

The next step is to allow ingress traffic to the ``/details`` endpoint:

.. literalinclude:: ../../../examples/kubernetes/servicemesh/policy/allow-ingress-cluster.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/policy/allow-ingress-cluster.yaml

.. code-block:: shell-session

    $ curl -s --fail http://"$HTTP_INGRESS"/details/1
    {"id":1,"author":"William Shakespeare","year":1595,"type":"paperback","pages":200,"publisher":"PublisherA","language":"English","ISBN-10":"1234567890","ISBN-13":"123-1234567890"}
    $ kubectl exec -it deployment/client -- curl -s http://$HTTP_INGRESS/details/1
    {"id":1,"author":"William Shakespeare","year":1595,"type":"paperback","pages":200,"publisher":"PublisherA","language":"English","ISBN-10":"1234567890","ISBN-13":"123-1234567890"}

NetworkPolicy that selects ``reserved:ingress`` and allows egress
to specific identities could also be used. But in general, it's probably more
reliable to allow all traffic from the ``reserved:ingress`` identity to all
``cluster`` identities, given that Cilium Ingress is part of the networking
infrastructure.
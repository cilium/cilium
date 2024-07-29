.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

*************************
External Lock-down Policy
*************************

By default, all the external traffic is allowed. Let's apply a `CiliumNetworkPolicy` to lock down external traffic.

.. literalinclude:: ../../../examples/kubernetes/servicemesh/policy/external-lockdown.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/policy/external-lockdown.yaml

With this policy applied, any request originating from outside the cluster will be rejected with a ``403 Forbidden``

.. code-block:: shell-session

    $ curl --fail -v http://"$HTTP_INGRESS"/details/1
    *   Trying 172.18.255.194:80...
    * Connected to 172.18.255.194 (172.18.255.194) port 80
    > GET /details/1 HTTP/1.1
    > Host: 172.18.255.194
    > User-Agent: curl/8.6.0
    > Accept: */*
    >
    < HTTP/1.1 403 Forbidden
    < content-length: 15
    < content-type: text/plain
    < date: Thu, 29 Feb 2024 12:59:54 GMT
    < server: envoy
    * The requested URL returned error: 403
    * Closing connection
    curl: (22) The requested URL returned error: 403

    # Capture hubble flows in another terminal
    $ kubectl --namespace=kube-system exec -i -t cilium-xjl4x -- hubble observe -f --identity ingress
    Defaulted container "cilium-agent" out of: cilium-agent, config (init), mount-cgroup (init), apply-sysctl-overwrites (init), mount-bpf-fs (init), wait-for-node-init (init), clean-cilium-state (init), install-cni-binaries (init)
    Feb 29 13:00:29.389: 172.18.0.1:53866 (ingress) -> kube-system/cilium-ingress:80 (world) http-request DROPPED (HTTP/1.1 GET http://172.18.255.194/details/1)
    Feb 29 13:00:29.389: 172.18.0.1:53866 (ingress) <- kube-system/cilium-ingress:80 (world) http-response FORWARDED (HTTP/1.1 403 0ms (GET http://172.18.255.194/details/1))

Let's check if in-cluster traffic to the Ingress endpoint is still allowed:

.. parsed-literal::

    # The test-application.yaml contains a client pod with curl available
    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/test-application.yaml
    $ kubectl exec -it deployment/client -- curl -s http://$HTTP_INGRESS/details/1
    {"id":1,"author":"William Shakespeare","year":1595,"type":"paperback","pages":200,"publisher":"PublisherA","language":"English","ISBN-10":"1234567890","ISBN-13":"123-1234567890"}%

Another common use case is to allow only a specific set of IP addresses to access the Ingress. This can be achieved via
the below policy

.. literalinclude:: ../../../examples/kubernetes/servicemesh/policy/allow-ingress-cidr.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/policy/allow-ingress-cidr.yaml

.. code-block:: shell-session

    $ curl -s --fail http://"$HTTP_INGRESS"/details/1
    {"id":1,"author":"William Shakespeare","year":1595,"type":"paperback","pages":200,"publisher":"PublisherA","language":"English","ISBN-10":"1234567890","ISBN-13":"123-1234567890"}

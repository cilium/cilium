.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _proxy_visibility:

***************************
Layer 7 Protocol Visibility
***************************

.. note::

    This feature requires enabling L7 Proxy support.

While :ref:`monitor` provides introspection into datapath state, by default, it
will only provide visibility into L3/L4 packet events. If you want L7
protocol visibility, you can use L7 Cilium Network Policies (see :ref:`l7_policy`).


.. note::

    Historically, it had been possible to enable L7 visibility using Pod
    annotations (``policy.cilium.io/proxy-visibility``). This method is
    no longer supported and we recommend users to switch to L7 policies instead.

To enable visibility for L7 traffic, create a ``CiliumNetworkPolicy`` that specifies
L7 rules. Traffic flows matching a L7 rule in a ``CiliumNetworkPolicy`` will become
visible to Cilium and, thus, can be exposed to the end user. It's important to 
remember that L7 network policies not only enables visibility but also restrict 
what traffic is allowed to flow in and out of a Pod.


The following example enables visibility for DNS (TCP/UDP/53) and HTTP
(ports TCP/80 and TCP/8080) traffic within the ``default`` namespace by
specifying two L7 rules -- one for DNS and one for HTTP. It also restricts
egress communication and drops anything that is not matched. L7 matching
conditions on the rules have been omitted or wildcarded, which will
permit all requests that match the L4 section of each rule:


.. code-block:: yaml

      apiVersion: "cilium.io/v2"
      kind: CiliumNetworkPolicy
      metadata:
        name: "l7-visibility"
      spec:
        endpointSelector:
          matchLabels:
            "k8s:io.kubernetes.pod.namespace": default
        egress:
        - toPorts:
          - ports:
            - port: "53"
              protocol: ANY
            rules:
              dns:
              - matchPattern: "*"
        - toEndpoints:
          - matchLabels:
              "k8s:io.kubernetes.pod.namespace": default
          toPorts:
          - ports:
            - port: "80"
              protocol: TCP
            - port: "8080"
              protocol: TCP
            rules:
              http: [{}]

Based on the above policy, Cilium will pick up all TCP/UDP/53, TCP/80 and TCP/8080 
egress traffic from Pods in the ``default`` namespace and redirect it to the 
proxy (see :ref:`proxy_injection`) such that the output of ``cilium monitor`` or 
``hubble observe`` shows the L7 flow details. 
Below is the example of running ``hubble observe -f -t l7 -o compact`` command:

::

    default/testapp-5b9cc645cb-4slbs:45240 (ID:26450) -> kube-system/coredns-787d4945fb-bdmdq:53 (ID:9313) dns-request proxy FORWARDED (DNS Query web.default.svc.cluster.local. A)
    default/testapp-5b9cc645cb-4slbs:45240 (ID:26450) <- kube-system/coredns-787d4945fb-bdmdq:53 (ID:9313) dns-response proxy FORWARDED (DNS Answer "10.96.118.37" TTL: 30 (Proxy web.default.svc.cluster.local. A))
    default/testapp-5b9cc645cb-4slbs:33044 (ID:26450) -> default/echo-594485b8dc-fp57l:8080 (ID:32531) http-request FORWARDED (HTTP/1.1 GET http://web/)
    default/testapp-5b9cc645cb-4slbs:33044 (ID:26450) <- default/echo-594485b8dc-fp57l:8080 (ID:32531) http-response FORWARDED (HTTP/1.1 200 4ms (GET http://web/))



Security Implications
---------------------

Monitoring Layer 7 traffic involves security considerations for handling
potentially sensitive information, such as usernames, passwords, query
parameters, API keys, and others.

.. warning::

   By default, Hubble does not redact potentially sensitive information
   present in `Layer 7 Hubble Flows <https://github.com/cilium/cilium/tree/master/api/v1/flow#flow-Layer7>`_.

To harden security, Cilium provides the ``--hubble-redact-enabled`` option which
enables Hubble to handle sensitive information present in Layer 7 flows.
More specifically, it offers the following features for supported Layer 7 protocols:

* For HTTP: redacting URL query (GET) parameters (``--hubble-redact-http-urlquery``)
* For Kafka: redacting API key (``--hubble-redact-kafka-apikey``)
* For HTTP headers: redacting all headers except those defined in the ``--hubble-redact-http-headers-allow`` list or redacting only the headers defined in the ``--hubble-redact-http-headers-deny`` list

For more information on configuring Cilium, see :ref:`Cilium Configuration <configuration>`.

Limitations
-----------

* DNS visibility is available on egress only.

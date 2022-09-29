Service Mesh Troubleshooting
============================


Install the Cilium CLI
----------------------

.. include:: /installation/cli-download.rst

Generic
-------

 #. Validate that the ``ds/cilium`` as well as the ``deployment/cilium-operator`` pods
    are healthy and ready.

    .. code-block:: shell-session

       $ cilium status

Manual Verification of Setup
----------------------------

 #. Validate that the ``kubeProxyReplacement`` is set to either partial or strict.

    .. code-block:: shell-session

        $ kubectl exec -n kube-system ds/cilium -- cilium status
        ...
        KVStore:                 Ok   Disabled
        Kubernetes:              Ok   1.23 (v1.23.6) [linux/amd64]
        KubeProxyReplacement:    Strict   [eth0 192.168.49.2]

 #. Validate that runtime the values of ``enable-envoy-config`` and ``enable-ingress-controller``
    are true. Ingress controller flag is optional if customer only uses ``CiliumEnvoyConfig`` or
    ``CiliumClusterwideEnvoyConfig`` CRDs.

    .. code-block:: shell-session

        $ kubectl -n kube-system get cm cilium-config -o json | egrep "enable-ingress-controller|enable-envoy-config"
                "enable-envoy-config": "true",
                "enable-ingress-controller": "true",

Ingress Troubleshooting
-----------------------

Internally, the Cilium Ingress controller will create one Load Balancer service, one
``CiliumEnvoyConfig`` and one dummy Endpoint resource for each Ingress resource.


    .. code-block:: shell-session

        $ kubectl get ingress
        NAME            CLASS    HOSTS   ADDRESS        PORTS   AGE
        basic-ingress   cilium   *       10.97.60.117   80      16m

        # For dedicated Load Balancer mode
        $ kubectl get service cilium-ingress-basic-ingress
        NAME                           TYPE           CLUSTER-IP     EXTERNAL-IP    PORT(S)        AGE
        cilium-ingress-basic-ingress   LoadBalancer   10.97.60.117   10.97.60.117   80:31911/TCP   17m

        # For dedicated Load Balancer mode
        $ kubectl get cec cilium-ingress-default-basic-ingress
        NAME                                   AGE
        cilium-ingress-default-basic-ingress   18m

        # For shared Load Balancer mode
        $ kubectl get services -n kube-system cilium-ingress
        NAME             TYPE           CLUSTER-IP      EXTERNAL-IP     PORT(S)                      AGE
        cilium-ingress   LoadBalancer   10.111.109.99   10.111.109.99   80:32690/TCP,443:31566/TCP   38m

        # For shared Load Balancer mode
        $ kubectl get cec -n kube-system cilium-ingress
        NAME             AGE
        cilium-ingress   15m

 #. Validate that the Load Balancer service has either an external IP or FQDN assigned.
    If it's not available after a long time, please check the Load Balancer related
    documentation from your respective cloud provider.

 #. Check if there is any warning or error message while Cilium is trying to provision
    the ``CiliumEnvoyConfig`` resource. This is unlikely to happen for CEC resources
    originating from the Cilium Ingress controller.

    .. include:: /network/servicemesh/warning.rst


Connectivity Troubleshooting
----------------------------

This section is for troubleshooting connectivity issues mainly for Ingress resources, but
the same steps can be applied to manually configured ``CiliumEnvoyConfig`` resources as well.

It's best to have ``debug`` and ``debug-verbose`` enabled with below values. Kindly
note that any change of Cilium flags requires a restart of the Cilium agent and operator.

    .. code-block:: shell-session

        $ kubectl get -n kube-system cm cilium-config -o json | grep "debug"
                "debug": "true",
                "debug-verbose": "flow",

.. note::

    The Ingress traffic is always allowed to pass through Cilium, regardless of the related
    CiliumNetworkPolicy for underlying pods or endpoints.

The request normally traverses from LoadBalancer service to pre-assigned port of your
node, then gets forwarded to the Cilium Envoy proxy, and finally gets proxied to the actual
backend service.

 #. The first step between cloud Load Balancer to node port is out of Cilium scope. Please
    check related documentation from your respective cloud provider to make sure your
    clusters are configured properly.

 #. The second step could be checked by connecting with SSH to your underlying host, and
    sending the similar request to localhost on the relevant port:

    .. code-block:: shell-session

        $ kubectl get service cilium-ingress-basic-ingress
        NAME                           TYPE           CLUSTER-IP     EXTERNAL-IP    PORT(S)        AGE
        cilium-ingress-basic-ingress   LoadBalancer   10.97.60.117   10.97.60.117   80:31911/TCP   17m

        # After ssh to any of k8s node
        $ curl -v http://localhost:31911/
        *   Trying 127.0.0.1:31911...
        * TCP_NODELAY set
        * Connected to localhost (127.0.0.1) port 31911 (#0)
        > GET / HTTP/1.1
        > Host: localhost:31911
        > User-Agent: curl/7.68.0
        > Accept: */*
        >
        * Mark bundle as not supporting multiuse
        < HTTP/1.1 503 Service Unavailable
        < content-length: 19
        < content-type: text/plain
        < date: Thu, 07 Jul 2022 12:25:56 GMT
        < server: envoy
        <
        * Connection #0 to host localhost left intact

        # Flows for world identity
        $ kubectl -n kube-system exec ds/cilium -- hubble observe -f --identity 2
        Jul  7 12:28:27.970: 127.0.0.1:54704 <- 127.0.0.1:13681 http-response FORWARDED (HTTP/1.1 503 0ms (GET http://localhost:31911/))

    Alternatively, you can also send a request directly to the Envoy proxy port. For
    Ingress, the proxy port is randomly assigned by the Cilium Ingress controller. For
    manually configured ``CiliumEnvoyConfig`` resources, the proxy port is retrieved
    directly from the spec.

    .. code-block:: shell-session

        $  kubectl logs -f -n kube-system ds/cilium --timestamps | egrep "envoy|proxy"
        ...
        2022-07-08T08:05:13.986649816Z level=info msg="Adding new proxy port rules for cilium-ingress-default-basic-ingress:19672" proxy port name=cilium-ingress-default-basic-ingress subsys=proxy

        # After ssh to any of k8s node, send request to Envoy proxy port directly
        $ curl -v  http://localhost:19672
        *   Trying 127.0.0.1:19672...
        * TCP_NODELAY set
        * Connected to localhost (127.0.0.1) port 19672 (#0)
        > GET / HTTP/1.1
        > Host: localhost:19672
        > User-Agent: curl/7.68.0
        > Accept: */*
        >
        * Mark bundle as not supporting multiuse
        < HTTP/1.1 503 Service Unavailable
        < content-length: 19
        < content-type: text/plain
        < date: Fri, 08 Jul 2022 08:12:35 GMT
        < server: envoy

    If you see a response similar to the above, it means that the request is being
    redirected to proxy successfully. The http response will have one special header
    ``server: envoy`` accordingly. The same can be observed from ``hubble observe``
    command :ref:`hubble_troubleshooting`.

    The most common root cause is either that the Cilium Envoy proxy is not running
    on the node, or there is some other issue with CEC resource provisioning.

    .. code-block:: shell-session

        $ kubectl exec -n kube-system ds/cilium -- cilium status
        ...
        Controller Status:       49/49 healthy
        Proxy Status:            OK, ip 10.0.0.25, 6 redirects active on ports 10000-20000
        Global Identity Range:   min 256, max 65535

 #. Assuming that the above steps are done successfully, you can proceed to send a request via
    an external IP or via FQDN next.

    Double-check whether your backend service is up and healthy. The Envoy Discovery Service
    (EDS) has a name that follows the convention ``<namespace>/<service-name>:<port>``.

    .. code-block:: shell-session

        $ LB_IP=$(kubectl get ingress basic-ingress -o json | jq '.status.loadBalancer.ingress[0].ip' | jq -r .)
        $ curl -s http://$LB_IP/details/1
        no healthy upstream

        $ kubectl get cec cilium-ingress-default-basic-ingress -o json | jq '.spec.resources[] | select(.type=="EDS")'
        {
          "@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
          "connectTimeout": "5s",
          "name": "default/details:9080",
          "outlierDetection": {
            "consecutiveLocalOriginFailure": 2,
            "splitExternalLocalOriginErrors": true
          },
          "type": "EDS",
          "typedExtensionProtocolOptions": {
            "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
              "@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
              "useDownstreamProtocolConfig": {
                "http2ProtocolOptions": {}
              }
            }
          }
        }
        {
          "@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
          "connectTimeout": "5s",
          "name": "default/productpage:9080",
          "outlierDetection": {
            "consecutiveLocalOriginFailure": 2,
            "splitExternalLocalOriginErrors": true
          },
          "type": "EDS",
          "typedExtensionProtocolOptions": {
            "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
              "@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
              "useDownstreamProtocolConfig": {
                "http2ProtocolOptions": {}
              }
            }
          }
        }

    If everything is configured correctly, you will be able to see the flows from ``world`` (identity 2),
    ``ingress`` (identity 8) and your backend pod as per below.

    .. code-block:: shell-session

        # Flows for world identity
        $ kubectl exec -n kube-system ds/cilium -- hubble observe --identity 2 -f
        Defaulted container "cilium-agent" out of: cilium-agent, mount-cgroup (init), apply-sysctl-overwrites (init), mount-bpf-fs (init), clean-cilium-state (init)
        Jul  7 13:07:46.726: 192.168.49.1:59608 -> default/details-v1-5498c86cf5-cnt9q:9080 http-request FORWARDED (HTTP/1.1 GET http://10.97.60.117/details/1)
        Jul  7 13:07:46.727: 192.168.49.1:59608 <- default/details-v1-5498c86cf5-cnt9q:9080 http-response FORWARDED (HTTP/1.1 200 1ms (GET http://10.97.60.117/details/1))

        # Flows for Ingress identity (e.g. envoy proxy)
        $ kubectl exec -n kube-system ds/cilium -- hubble observe --identity 8 -f
        Defaulted container "cilium-agent" out of: cilium-agent, mount-cgroup (init), apply-sysctl-overwrites (init), mount-bpf-fs (init), clean-cilium-state (init)
        Jul  7 13:07:46.726: 10.0.0.95:42509 -> default/details-v1-5498c86cf5-cnt9q:9080 to-endpoint FORWARDED (TCP Flags: SYN)
        Jul  7 13:07:46.726: 10.0.0.95:42509 <- default/details-v1-5498c86cf5-cnt9q:9080 to-stack FORWARDED (TCP Flags: SYN, ACK)
        Jul  7 13:07:46.726: 10.0.0.95:42509 -> default/details-v1-5498c86cf5-cnt9q:9080 to-endpoint FORWARDED (TCP Flags: ACK)
        Jul  7 13:07:46.726: 10.0.0.95:42509 -> default/details-v1-5498c86cf5-cnt9q:9080 to-endpoint FORWARDED (TCP Flags: ACK, PSH)
        Jul  7 13:07:46.727: 10.0.0.95:42509 <- default/details-v1-5498c86cf5-cnt9q:9080 to-stack FORWARDED (TCP Flags: ACK, PSH)

        # Flows for backend pod, the identity can be retrieved via cilium identity list command
        $ kubectl exec -n kube-system ds/cilium -- hubble observe --identity 48847 -f
        Defaulted container "cilium-agent" out of: cilium-agent, mount-cgroup (init), apply-sysctl-overwrites (init), mount-bpf-fs (init), clean-cilium-state (init)
        Jul  7 13:07:46.726: 10.0.0.95:42509 -> default/details-v1-5498c86cf5-cnt9q:9080 to-endpoint FORWARDED (TCP Flags: SYN)
        Jul  7 13:07:46.726: 10.0.0.95:42509 <- default/details-v1-5498c86cf5-cnt9q:9080 to-stack FORWARDED (TCP Flags: SYN, ACK)
        Jul  7 13:07:46.726: 10.0.0.95:42509 -> default/details-v1-5498c86cf5-cnt9q:9080 to-endpoint FORWARDED (TCP Flags: ACK)
        Jul  7 13:07:46.726: 10.0.0.95:42509 -> default/details-v1-5498c86cf5-cnt9q:9080 to-endpoint FORWARDED (TCP Flags: ACK, PSH)
        Jul  7 13:07:46.726: 192.168.49.1:59608 -> default/details-v1-5498c86cf5-cnt9q:9080 http-request FORWARDED (HTTP/1.1 GET http://10.97.60.117/details/1)
        Jul  7 13:07:46.727: 10.0.0.95:42509 <- default/details-v1-5498c86cf5-cnt9q:9080 to-stack FORWARDED (TCP Flags: ACK, PSH)
        Jul  7 13:07:46.727: 192.168.49.1:59608 <- default/details-v1-5498c86cf5-cnt9q:9080 http-response FORWARDED (HTTP/1.1 200 1ms (GET http://10.97.60.117/details/1))
        Jul  7 13:08:16.757: 10.0.0.95:42509 <- default/details-v1-5498c86cf5-cnt9q:9080 to-stack FORWARDED (TCP Flags: ACK, FIN)
        Jul  7 13:08:16.757: 10.0.0.95:42509 -> default/details-v1-5498c86cf5-cnt9q:9080 to-endpoint FORWARDED (TCP Flags: ACK, FIN)

        # Sample output of cilium monitor
        $ ksysex ds/cilium -- cilium monitor
        level=info msg="Initializing dissection cache..." subsys=monitor
        -> endpoint 212 flow 0x3000e251 , identity ingress->61131 state new ifindex lxcfc90a8580fd6 orig-ip 10.0.0.192: 10.0.0.192:34219 -> 10.0.0.164:9080 tcp SYN
        -> stack flow 0x2481d648 , identity 61131->ingress state reply ifindex 0 orig-ip 0.0.0.0: 10.0.0.164:9080 -> 10.0.0.192:34219 tcp SYN, ACK
        -> endpoint 212 flow 0x3000e251 , identity ingress->61131 state established ifindex lxcfc90a8580fd6 orig-ip 10.0.0.192: 10.0.0.192:34219 -> 10.0.0.164:9080 tcp ACK
        -> endpoint 212 flow 0x3000e251 , identity ingress->61131 state established ifindex lxcfc90a8580fd6 orig-ip 10.0.0.192: 10.0.0.192:34219 -> 10.0.0.164:9080 tcp ACK
        -> Request http from 0 ([reserved:world]) to 212 ([k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=default k8s:io.cilium.k8s.policy.cluster=minikube k8s:io.cilium.k8s.policy.serviceaccount=bookinfo-details k8s:io.kubernetes.pod.namespace=default k8s:version=v1 k8s:app=details]), identity 2->61131, verdict Forwarded GET http://10.99.74.157/details/1 => 0
        -> stack flow 0x2481d648 , identity 61131->ingress state reply ifindex 0 orig-ip 0.0.0.0: 10.0.0.164:9080 -> 10.0.0.192:34219 tcp ACK
        -> Response http to 0 ([reserved:world]) from 212 ([k8s:io.kubernetes.pod.namespace=default k8s:version=v1 k8s:app=details k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=default k8s:io.cilium.k8s.policy.cluster=minikube k8s:io.cilium.k8s.policy.serviceaccount=bookinfo-details]), identity 61131->2, verdict Forwarded GET http://10.99.74.157/details/1 => 200

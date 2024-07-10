.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _local-redirect-policy:

*********************
Local Redirect Policy
*********************

This document explains how to configure Cilium's Local Redirect Policy, that
enables pod traffic destined to an IP address and port/protocol tuple
or Kubernetes service to be redirected locally to backend pod(s) within a node,
using eBPF. The namespace of backend pod(s) need to match with that of the policy.
The CiliumLocalRedirectPolicy is configured as a ``CustomResourceDefinition``.

.. admonition:: Video
  :class: attention

  Aside from this document, you can watch a video explanation of Cilium's Local Redirect Policy on `eCHO episode 39: Local Redirect Policy <https://www.youtube.com/watch?v=BT_gdlhjiQc&t=176s>`__.

There are two types of Local Redirect Policies supported. When traffic for a
Kubernetes service needs to be redirected, use the `ServiceMatcher` type. The
service needs to be of type ``clusterIP``.
When traffic matching IP address and port/protocol, that doesn't belong to
any Kubernetes service, needs to be redirected, use the `AddressMatcher` type.

The policies can be gated by Kubernetes Role-based access control (RBAC)
framework. See the official `RBAC documentation
<https://kubernetes.io/docs/reference/access-authn-authz/rbac/>`_.

When policies are applied, matched pod traffic is redirected. If desired, RBAC
configurations can be used such that application developers can not escape
the redirection.

Prerequisites
=============

.. note::

   Local Redirect Policy feature requires a v4.19.x or more recent Linux kernel.

.. include:: ../../installation/k8s-install-download-release.rst

The Cilium Local Redirect Policy feature relies on :ref:`kubeproxy-free`,
follow the guide to create a new deployment. Enable the feature by setting
the ``localRedirectPolicy`` value to ``true``.

.. parsed-literal::

   helm upgrade cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --reuse-values \\
     --set localRedirectPolicy=true


Rollout the operator and agent pods to make the changes effective:

.. code-block:: shell-session

    $ kubectl rollout restart deploy cilium-operator -n kube-system
    $ kubectl rollout restart ds cilium -n kube-system


Verify that Cilium agent and operator pods are running.

.. code-block:: shell-session

    $ kubectl -n kube-system get pods -l k8s-app=cilium
    NAME           READY   STATUS    RESTARTS   AGE
    cilium-5ngzd   1/1     Running   0          3m19s

    $ kubectl -n kube-system get pods -l name=cilium-operator
    NAME                               READY   STATUS    RESTARTS   AGE
    cilium-operator-544b4d5cdd-qxvpv   1/1     Running   0          3m19s

Validate that the Cilium Local Redirect Policy CRD has been registered.

.. code-block:: shell-session

	   $ kubectl get crds
	   NAME                              CREATED AT
	   [...]
	   ciliumlocalredirectpolicies.cilium.io              2020-08-24T05:31:47Z

Create backend and client pods
==============================

Deploy a backend pod where traffic needs to be redirected to based on the
configurations specified in a CiliumLocalRedirectPolicy. The metadata
labels and container port and protocol respectively match with the labels,
port and protocol fields specified in the CiliumLocalRedirectPolicy custom
resources that will be created in the next step.

.. literalinclude:: ../../../examples/kubernetes-local-redirect/backend-pod.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-local-redirect/backend-pod.yaml

Verify that the pod is running.

.. code-block:: shell-session

    $ kubectl get pods | grep lrp-pod
    lrp-pod                      1/1     Running   0          46s

Deploy a client pod that will generate traffic which will be redirected based on
the configurations specified in the CiliumLocalRedirectPolicy.

.. parsed-literal::

   $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-sw-app.yaml
   $ kubectl wait pod/mediabot --for=condition=Ready
   $ kubectl get pods
   NAME                             READY   STATUS    RESTARTS   AGE
   pod/mediabot                     1/1     Running   0          14s

Create Cilium Local Redirect Policy Custom Resources
=====================================================
There are two types of configurations supported in the CiliumLocalRedirectPolicy
in order to match the traffic that needs to be redirected.

.. _AddressMatcher:

AddressMatcher
---------------

This type of configuration is specified using an IP address and a Layer 4 port/protocol.
When multiple ports are specified for frontend in ``toPorts``, the ports need
to be named. The port names will be used to map frontend ports with backend ports.

Verify that the ports specified in ``toPorts`` under ``redirectBackend``
exist in the backend pod spec.

The example shows how to redirect from traffic matching, IP address ``169.254.169.254``
and Layer 4 port ``8080`` with protocol ``TCP``, to a backend pod deployed with
labels ``app=proxy`` and Layer 4 port ``80`` with protocol ``TCP``. The
``localEndpointSelector`` set to ``app=proxy`` in the policy is used to select
the backend pods where traffic is redirected to.

Create a custom resource of type CiliumLocalRedirectPolicy with ``addressMatcher``
configuration.

.. literalinclude:: ../../../examples/kubernetes-local-redirect/lrp-addrmatcher.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-local-redirect/lrp-addrmatcher.yaml

Verify that the custom resource is created.

.. code-block:: shell-session

    $ kubectl get ciliumlocalredirectpolicies | grep lrp-addr
    NAME           AGE
    lrp-addr       20h

Verify that Cilium's eBPF kube-proxy replacement created a ``LocalRedirect``
service entry with the backend IP address of that of the ``lrp-pod`` that was
selected by the policy. Make sure that ``cilium-dbg service list`` is run
in Cilium pod running on the same node as ``lrp-pod``.

.. code-block:: shell-session

    $ kubectl describe pod lrp-pod  | grep 'IP:'
    IP:           10.16.70.187

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-5ngzd -- cilium-dbg service list
    ID   Frontend               Service Type       Backend
    [...]
    4    172.20.0.51:80         LocalRedirect      1 => 10.16.70.187:80

Invoke a curl command from the client pod to the IP address and port
configuration specified in the ``lrp-addr`` custom resource above.

.. code-block:: shell-session

    $ kubectl exec mediabot -- curl -I -s http://169.254.169.254:8080/index.html
    HTTP/1.1 200 OK
    Server: nginx/1.19.2
    Date: Fri, 28 Aug 2020 01:33:34 GMT
    Content-Type: text/html
    Content-Length: 612
    Last-Modified: Tue, 11 Aug 2020 14:50:35 GMT
    Connection: keep-alive
    ETag: "5f32b03b-264"
    Accept-Ranges: bytes

Verify that the traffic was redirected to the ``lrp-pod`` that was deployed.
``tcpdump`` should be run on the same node that ``lrp-pod`` is running on.

.. code-block:: shell-session

    $ sudo tcpdump -i any -n port 80
    tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
    listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
    01:36:24.608566 IP 10.16.215.55.60876 > 10.16.70.187.80: Flags [S], seq 2119454273, win 28200, options [mss 1410,sackOK,TS val 2541637677 ecr 0,nop,wscale 7], length 0
    01:36:24.608600 IP 10.16.70.187.80 > 10.16.215.55.60876: Flags [S.], seq 1315636594, ack 2119454274, win 27960, options [mss 1410,sackOK,TS val 2962246962 ecr 2541637677,nop,wscale 7], length 0
    01:36:24.608638 IP 10.16.215.55.60876 > 10.16.70.187.80: Flags [.], ack 1, win 221, options [nop,nop,TS val 2541637677 ecr 2962246962], length 0
    01:36:24.608867 IP 10.16.215.55.60876 > 10.16.70.187.80: Flags [P.], seq 1:96, ack 1, win 221, options [nop,nop,TS val 2541637677 ecr 2962246962], length 95: HTTP: HEAD /index.html HTTP/1.1
    01:36:24.608876 IP 10.16.70.187.80 > 10.16.215.55.60876: Flags [.], ack 96, win 219, options [nop,nop,TS val 2962246962 ecr 2541637677], length 0
    01:36:24.609007 IP 10.16.70.187.80 > 10.16.215.55.60876: Flags [P.], seq 1:239, ack 96, win 219, options [nop,nop,TS val 2962246962 ecr 2541637677], length 238: HTTP: HTTP/1.1 200 OK
    01:36:24.609052 IP 10.16.215.55.60876 > 10.16.70.187.80: Flags [.], ack 239, win 229, options [nop,nop,TS val 2541637677 ecr 2962246962], length 0

.. _ServiceMatcher:

ServiceMatcher
---------------

This type of configuration is specified using Kubernetes service name and namespace
for which traffic needs to be redirected. The service must be of type ``clusterIP``.
When ``toPorts`` under ``redirectFrontend`` are not specified, traffic for
all the service ports will be redirected. However, if traffic destined to only
a subset of ports needs to be redirected, these ports need to be specified in the spec.
Additionally, when multiple service ports are specified in the spec, they must be
named. The port names will be used to map frontend ports with backend ports.
Verify that the ports specified in ``toPorts`` under ``redirectBackend``
exist in the backend pod spec. The ``localEndpointSelector`` set to ``app=proxy``
in the policy is used to select the backend pods where traffic is redirected to.

When a policy of this type is applied, the existing service entry
created by Cilium's eBPF kube-proxy replacement will be replaced with a new
service entry of type ``LocalRedirect``. This entry may only have node-local backend pods.

The example shows how to redirect from traffic matching ``my-service``, to a
backend pod deployed with labels ``app=proxy`` and Layer 4 port ``80``
with protocol ``TCP``. The ``localEndpointSelector`` set to ``app=proxy`` in the
policy is used to select the backend pods where traffic is redirected to.

Deploy the Kubernetes service for which traffic needs to be redirected.

.. literalinclude:: ../../../examples/kubernetes-local-redirect/k8s-svc.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-local-redirect/k8s-svc.yaml

Verify that the service is created.

.. code-block:: shell-session

    $ kubectl get service | grep 'my-service'
    my-service   ClusterIP   172.20.0.51   <none>        80/TCP     2d7h

Verify that Cilium's eBPF kube-proxy replacement created a ``ClusterIP``
service entry.

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system ds/cilium -- cilium-dbg service list
    ID   Frontend               Service Type   Backend
    [...]
    4    172.20.0.51:80         ClusterIP

Create a custom resource of type CiliumLocalRedirectPolicy with ``serviceMatcher``
configuration.

.. literalinclude:: ../../../examples/kubernetes-local-redirect/lrp-svcmatcher.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-local-redirect/lrp-svcmatcher.yaml

Verify that the custom resource is created.

.. code-block:: shell-session

    $ kubectl get ciliumlocalredirectpolicies | grep svc
    NAME               AGE
    lrp-svc   20h

Verify that entry Cilium's eBPF kube-proxy replacement updated the
service entry with type ``LocalRedirect`` and the node-local backend
selected by the policy. Make sure to run ``cilium-dbg service list`` in Cilium pod
running on the same node as ``lrp-pod``.

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-5ngzd -- cilium-dbg service list
    ID   Frontend               Service Type       Backend
    [...]
    4    172.20.0.51:80         LocalRedirect      1 => 10.16.70.187:80

Invoke a curl command from the client pod to the Cluster IP address and port of
``my-service`` specified in the ``lrp-svc`` custom resource above.

.. code-block:: shell-session

    $ kubectl exec mediabot -- curl -I -s http://172.20.0.51/index.html
    HTTP/1.1 200 OK
    Server: nginx/1.19.2
    Date: Fri, 28 Aug 2020 01:50:50 GMT
    Content-Type: text/html
    Content-Length: 612
    Last-Modified: Tue, 11 Aug 2020 14:50:35 GMT
    Connection: keep-alive
    ETag: "5f32b03b-264"
    Accept-Ranges: bytes

Verify that the traffic was redirected to the ``lrp-pod`` that was deployed.
``tcpdump`` should be run on the same node that ``lrp-pod`` is running on.

.. code-block:: shell-session

    $ kubectl describe pod lrp-pod  | grep 'IP:'
    IP:           10.16.70.187

.. code-block:: shell-session

    $ sudo tcpdump -i any -n port 80
    tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
    listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
    01:36:24.608566 IP 10.16.215.55.60186 > 10.16.70.187.80: Flags [S], seq 2119454273, win 28200, options [mss 1410,sackOK,TS val 2541637677 ecr 0,nop,wscale 7], length 0
    01:36:24.608600 IP 10.16.70.187.80 > 10.16.215.55.60876: Flags [S.], seq 1315636594, ack 2119454274, win 27960, options [mss 1410,sackOK,TS val 2962246962 ecr 2541637677,nop,wscale 7], length 0
    01:36:24.608638 IP 10.16.215.55.60876 > 10.16.70.187.80: Flags [.], ack 1, win 221, options [nop,nop,TS val 2541637677 ecr 2962246962], length 0
    01:36:24.608867 IP 10.16.215.55.60876 > 10.16.70.187.80: Flags [P.], seq 1:96, ack 1, win 221, options [nop,nop,TS val 2541637677 ecr 2962246962], length 95: HTTP: HEAD /index.html HTTP/1.1
    01:36:24.608876 IP 10.16.70.187.80 > 10.16.215.55.60876: Flags [.], ack 96, win 219, options [nop,nop,TS val 2962246962 ecr 2541637677], length 0
    01:36:24.609007 IP 10.16.70.187.80 > 10.16.215.55.60876: Flags [P.], seq 1:239, ack 96, win 219, options [nop,nop,TS val 2962246962 ecr 2541637677], length 238: HTTP: HTTP/1.1 200 OK
    01:36:24.609052 IP 10.16.215.55.60876 > 10.16.70.187.80: Flags [.], ack 239, win 229, options [nop,nop,TS val 2541637677 ecr 2962246962], length 0

Limitations
===========
When you create a Local Redirect Policy, traffic for all the new connections
that get established after the policy is enforced will be redirected. But if
you have existing active connections to remote pods that match the configurations
specified in the policy, then these might not get redirected. To ensure all
such connections are redirected locally, restart the client pods after
configuring the CiliumLocalRedirectPolicy.

Local Redirect Policy updates are currently not supported. If there are any
changes to be made, delete the existing policy, and re-create a new one.

Use Cases
=========
Local Redirect Policy allows Cilium to support the following use cases:

Node-local DNS cache
--------------------
`DNS node-cache <https://github.com/kubernetes/dns>`_ listens on a static IP to intercept
traffic from application pods to the cluster's DNS service VIP by default, which will be
bypassed when Cilium is handling service resolution at or before the veth interface of the
application pod. To enable the DNS node-cache in a Cilium cluster, the following example
steers traffic to a local DNS node-cache which runs as a normal pod.

* Deploy DNS node-cache in pod namespace.

  .. tabs::

    .. group-tab:: Quick Deployment

        Deploy DNS node-cache.

        .. note::

           * The example yaml is populated with default values for ``__PILLAR_LOCAL_DNS__`` and
             ``__PILLAR_DNS_DOMAIN__``.
           * If you have a different deployment, please follow the official `NodeLocal DNSCache Configuration
             <https://kubernetes.io/docs/tasks/administer-cluster/nodelocaldns/#configuration>`_
             to fill in the required template variables ``__PILLAR__LOCAL__DNS__``, ``__PILLAR__DNS__DOMAIN__``,
             and ``__PILLAR__DNS__SERVER__`` before applying the yaml.

        .. parsed-literal::

            $ wget \ |SCM_WEB|\/examples/kubernetes-local-redirect/node-local-dns.yaml

            $ kubedns=$(kubectl get svc kube-dns -n kube-system -o jsonpath={.spec.clusterIP}) && sed -i "s/__PILLAR__DNS__SERVER__/$kubedns/g;" node-local-dns.yaml

            $ kubectl apply -f node-local-dns.yaml

    .. group-tab:: Manual Configuration

         * Follow the official `NodeLocal DNSCache Configuration
           <https://kubernetes.io/docs/tasks/administer-cluster/nodelocaldns/#configuration>`_
           to fill in the required template variables ``__PILLAR__LOCAL__DNS__``, ``__PILLAR__DNS__DOMAIN__``,
           and ``__PILLAR__DNS__SERVER__`` before applying the yaml.

         * Make sure to use a Node-local DNS image with a release version >= 1.15.16.
           This is to ensure that we have a knob to disable dummy network interface creation/deletion in
           Node-local DNS when we deploy it in non-host namespace.

         * Modify Node-local DNS cache's deployment yaml to pass these additional arguments to node-cache:
           ``-skipteardown=true``, ``-setupinterface=false``, and ``-setupiptables=false``.

         * Modify Node-local DNS cache's deployment yaml to put it in non-host namespace by setting
           ``hostNetwork: false`` for the daemonset.

         * In the Corefile, bind to ``0.0.0.0`` instead of the static IP.

         * In the Corefile, let CoreDNS serve health-check on its own IP instead of the static IP by
           removing the host IP string after health plugin.

         * Modify Node-local DNS cache's deployment yaml to point readiness probe to its own IP by
           removing the ``host`` field under ``readinessProbe``.

* Deploy Local Redirect Policy (LRP) to steer DNS traffic to the node local dns cache.

  .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-local-redirect/node-local-dns-lrp.yaml

  .. note::

      * The LRP above uses ``kube-dns`` for the cluster DNS service, however if your cluster DNS service is different,
        you will need to modify this example LRP to specify it.
      * The namespace specified in the LRP above is set to the same namespace as the cluster's dns service.
      * The LRP above uses the same port names ``dns`` and ``dns-tcp`` as the example quick deployment yaml, you will
        need to modify those to match your deployment if they are different.

After all ``node-local-dns`` pods are in ready status, DNS traffic will now go to the local node-cache first.
You can verify by checking the DNS cache's metrics ``coredns_dns_request_count_total`` via curling
``<node-local-dns pod IP>:9253/metrics``, the metric should increment as new DNS requests being issued from
application pods are now redirected to the ``node-local-dns`` pod.

In the absence of a node-local DNS cache, DNS queries from application pods
will get directed to cluster DNS pods backed by the ``kube-dns`` service.

* Troubleshooting

    If DNS requests are failing to resolve, check the following:

        - Ensure that the node-local DNS cache pods are running and ready.

         .. code-block:: shell-session

            $ kubectl --namespace kube-system get pods --selector=k8s-app=node-local-dns
            NAME                   READY   STATUS    RESTARTS   AGE
            node-local-dns-72r7m   1/1     Running   0          2d2h
            node-local-dns-gc5bx   1/1     Running   0          2d2h

        - Check if the local redirect policy has been applied correctly on all the cilium agent pods.

         .. code-block:: shell-session

            $ kubectl exec -it cilium-mhnhz -n kube-system -- cilium-dbg lrp list
            LRP namespace   LRP name       FrontendType                Matching Service
            kube-system     nodelocaldns   clusterIP + all svc ports   kube-system/kube-dns
                            |              10.96.0.10:53/UDP -> 10.244.1.49:53(kube-system/node-local-dns-72r7m),
                            |              10.96.0.10:53/TCP -> 10.244.1.49:53(kube-system/node-local-dns-72r7m),

        - Check if the corresponding local redirect service entry has been created. If the service entry is missing,
          there might have been a race condition in applying the policy and the node-local DNS DaemonSet pod resources.
          As a workaround, you can restart the node-local DNS DaemonSet pods. File a `GitHub issue <https://github.com/cilium/cilium/issues/new/choose>`_
          with a :ref:`sysdump <sysdump>` if the issue persists.

         .. code-block:: shell-session

            $ kubectl exec -it cilium-mhnhz -n kube-system -- cilium-dbg service list | grep LocalRedirect
            11   10.96.0.10:53      LocalRedirect   1 => 10.244.1.49:53 (active)

kiam redirect on EKS
--------------------
`kiam <https://github.com/uswitch/kiam>`_ agent runs on each node in an EKS
cluster, and intercepts requests going to the AWS metadata server to fetch
security credentials for pods.

- In order to only redirect traffic from pods to the kiam agent, and pass
  traffic from the kiam agent to the AWS metadata server without any redirection,
  we need the socket lookup functionality in the datapath. This functionality
  requires v5.1.16, v5.2.0 or more recent Linux kernel. Make sure the kernel
  version installed on EKS cluster nodes satisfies these requirements.

- Deploy `kiam <https://github.com/uswitch/kiam>`_ using helm charts.

  .. code-block:: shell-session

      $ helm repo add uswitch https://uswitch.github.io/kiam-helm-charts/charts/
      $ helm repo update
      $ helm install --set agent.host.iptables=false --set agent.whitelist-route-regexp=meta-data kiam uswitch/kiam

  - The above command may provide instructions to prepare kiam in the cluster.
    Follow the instructions before continuing.

  - kiam must run in the ``hostNetwork`` mode and without the "--iptables" argument.
    The install instructions above ensure this by default.

- Deploy the Local Redirect Policy to redirect pod traffic to the deployed kiam agent.

  .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-local-redirect/kiam-lrp.yaml

.. note::

    - The ``addressMatcher`` ip address in the Local Redirect Policy is set to
      the ip address of the AWS metadata server and the ``toPorts`` port
      to the default HTTP server port. The ``toPorts`` field under
      ``redirectBackend`` configuration in the policy is set to the port that
      the kiam agent listens on. The port is passed as "--port" argument in
      the ``kiam-agent DaemonSet``.
    - The Local Redirect Policy namespace is set to the namespace
      in which kiam-agent DaemonSet is deployed.

- Once all the kiam agent pods are in ``Running`` state, the metadata requests
  from application pods will get redirected to the node-local kiam agent pods.
  You can verify this by running a curl command to the AWS metadata server from
  one of the application pods, and tcpdump command on the same EKS cluster node as the
  pod. Following is an example output, where ``192.169.98.118`` is the ip
  address of an application pod, and ``192.168.60.99`` is the ip address of the
  kiam agent running on the same node as the application pod.

  .. code-block:: shell-session

      $ kubectl exec app-pod -- curl -s -w "\n" -X GET http://169.254.169.254/latest/meta-data/
      ami-id
      ami-launch-index
      ami-manifest-path
      block-device-mapping/
      events/
      hostname
      iam/
      identity-credentials/
      (...)

  .. code-block:: shell-session

      $ sudo tcpdump -i any -enn "(port 8181) and (host 192.168.60.99 and 192.168.98.118)"
      tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
      listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
      05:16:05.229597  In de:e4:e9:94:b5:9f ethertype IPv4 (0x0800), length 76: 192.168.98.118.47934 > 192.168.60.99.8181: Flags [S], seq 669026791, win 62727, options [mss 8961,sackOK,TS val 2539579886 ecr 0,nop,wscale 7], length 0
      05:16:05.229657 Out 56:8f:62:18:6f:85 ethertype IPv4 (0x0800), length 76: 192.168.60.99.8181 > 192.168.98.118.47934: Flags [S.], seq 2355192249, ack 669026792, win 62643, options [mss 8961,sackOK,TS val 4263010641 ecr 2539579886,nop,wscale 7], length 0

Advanced configurations
=======================
When a local redirect policy is applied, cilium BPF datapath redirects traffic going to the policy frontend
(identified by ip/port/protocol tuple) address to a node-local backend pod selected by the policy.
However, for traffic originating from a node-local backend pod destined to the policy frontend, users may want to
skip redirecting the traffic back to the node-local backend pod, and instead forward the traffic to the original frontend.
This behavior can be enabled by setting the ``skipRedirectFromBackend`` flag to ``true`` in the local redirect policy spec.
The configuration is only supported with socket-based load-balancing, and requires ``SO_NETNS_COOKIE`` feature
available in Linux kernel version >= 5.8.

.. note::

    In order to enable this configuration starting Cilium version 1.16.0, previously applied local redirect policies
    and policies selected backend pods need to be deleted, and re-created.

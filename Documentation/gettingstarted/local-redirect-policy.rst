.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _local-redirect-policy:

*****************************
Local Redirect Policy (beta)
*****************************

This document explains how to configure Cilium's Local Redirect Policy, that
enables pod traffic destined to an IP address and port/protocol tuple
or Kubernetes service to be redirected locally to a backend pod within a node.
The CiliumLocalRedirectPolicy is configured as a ``CustomResourceDefinition``.
CiliumLocalRedirectPolicy is namespace-aware, while CiliumClusterwideLocalRedirectPolicy
is a cluster-scoped version that specifies cluster-wide policies.

There are two types of Local Redirect Policies supported. When traffic for a
Kubernetes service needs to be redirected, use the `ServiceMatcher` type. The
service needs to be of type ``clusterIP``.
When traffic matching IP address and layer port/protocol, that doesn't belong to
any Kubernetes service, needs to be redirected, use the `AddressMatcher` type.

The policies can be gated by Kubernetes Role-based access control (RBAC)
framework. See the official `RBAC documentation
<https://kubernetes.io/docs/reference/access-authn-authz/rbac/>`_.

When policies are applied, matched pod traffic is redirected. If desired, RBAC
configurations can be used such that application developers can not escape
the redirection.


.. include:: ../beta.rst

Deploy Cilium
===============

.. include:: k8s-install-download-release.rst

The Cilium Local Redirect Policy feature relies on :ref:`Kube-proxy free
feature <kubeproxy-free>`, follow the guide to create a new deployment.

Verify that Cilium agent pod is running.

.. code-block:: bash

    $ kubectl -n kube-system get pods -l k8s-app=cilium
    NAME           READY   STATUS    RESTARTS   AGE
    cilium-5ngzd   1/1     Running   0          3m19s


Validate that the Cilium Local Redirect Policy CRD has been registered.

.. code-block:: bash

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

.. literalinclude:: ../../examples/kubernetes-local-redirect/backend-pod.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-local-redirect/backend-pod.yaml

Verify that the pod is running.

.. code-block:: bash

    $ kubectl get pods | grep lrp-pod
    lrp-pod                      1/1     Running   0          46s

Deploy a client pod that will generate traffic which will be redirected based on
the configurations specified in the CiliumLocalRedirectPolicy.

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-sw-app.yaml
    $ kubectl get po
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
labels ``app=proxy`` and Layer 4 port ``80`` with protocol ``TCP``.

Create a custom resource of type CiliumLocalRedirectPolicy with ``addressMatcher``
configuration.

.. literalinclude:: ../../examples/kubernetes-local-redirect/lrp-addrmatcher.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-local-redirect/lrp-addrmatcher.yaml

Verify that the custom resource is created.

.. code-block:: bash

    $ kubectl get ciliumlocalredirectpolicies | grep lrp-addr
    NAME           AGE
    lrp-addr       20h

Verify that Cilium's eBPF kube-proxy replacement created a ``LocalRedirect``
service entry with the backend IP address of that of the ``lrp-pod`` that was
selected by the policy.

.. code-block:: bash

    $ kubectl describe pod lrp-pod  | grep 'IP:'
    IP:           10.16.70.187

.. code-block:: bash

    $ kubectl exec -it -n kube-system cilium-5ngzd -- cilium service list
    ID   Frontend               Service Type   Backend
    [...]
    4    172.20.0.51:80         ClusterIP      1 => 10.16.70.187:80

Invoke a curl command from the client pod to the IP address and port
configuration specified in the ``lrp-addr`` custom resource above.

.. code-block:: bash

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

.. parsed-literal::

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
exist in the backend pod spec.

When a policy of this type is applied, the existing service entry
created by Cilium's eBPF kube-proxy replacement will be replaced with a new
service entry of type ``LocalRedirect``. This entry may only have node-local backend pods.

The example shows how to redirect from traffic matching ``my-service``, to a
backend pod deployed with labels ``app=proxy`` and Layer 4 port ``80``
with protocol ``TCP``.

Deploy the Kubernetes service for which traffic needs to be redirected.

.. literalinclude:: ../../examples/kubernetes-local-redirect/k8s-svc.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-local-redirect/k8s-svc.yaml

Verify that the service is created.

.. code-block:: bash

    $ kubectl get service | grep 'my-service'
    my-service   ClusterIP   172.20.0.51   <none>        80/TCP     2d7h

Verify that Cilium's eBPF kube-proxy replacement created a ``ClusterIP``
service entry.

.. code-block:: bash

    $ kubectl exec -it -n kube-system cilium-5ngzd -- cilium service list
    ID   Frontend               Service Type   Backend
    [...]
    4    172.20.0.51:80         ClusterIP

Create a custom resource of type CiliumLocalRedirectPolicy with ``serviceMatcher``
configuration.

.. literalinclude:: ../../examples/kubernetes-local-redirect/lrp-svcmatcher.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-local-redirect/lrp-svcmatcher.yaml

Verify that the custom resource is created.

.. code-block:: bash

    $ kubectl get ciliumlocalredirectpolicies | grep svc
    NAME               AGE
    lrp-svc   20h

Verify that entry Cilium's eBPF kube-proxy replacement updated the
service entry with type ``LocalRedirect`` and the node-local backend
selected by the policy.

.. code-block:: bash

    $ kubectl exec -it -n kube-system cilium-5ngzd -- cilium service list
    ID   Frontend               Service Type       Backend
    [...]
    4    172.20.0.51:80         LocalRedirect      1 => 10.16.70.187:80

Invoke a curl command from the client pod to the Cluster IP address and port of
``my-service`` specified in the ``lrp-svc`` custom resource above.

.. code-block:: bash

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

.. code-block:: bash

    $ kubectl describe pod lrp-pod  | grep 'IP:'
    IP:           10.16.70.187

.. parsed-literal::

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




.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gsg_istio:

***********************
Integration with Istio
***********************

This page helps you get started using Istio with a Cilium-enabled Kubernetes cluster.
This document covers the following common aspects of Cilium's integration with Istio:

* Cilium configuration
* Istio configuration
* Demo application

Cilium Configuration
====================

The main goal of Cilium configuration is to ensure that traffic redirected to
Istio's `sidecar proxies <https://istio.io/latest/docs/ops/deployment/architecture/>`_ is not disrupted.
Disruptions can happen when you enable Cilium's ``kubeProxyReplacement`` feature  (see :ref:`kubeproxy-free` docs), 
which enables socket based load balancing inside a Pod.

To ensure that Cilium does not interfere with Istio, Cilium must be deployed
with the ``--config bpf-lb-sock-hostns-only=true`` cilium CLI flag or with the ``socketLB.hostNamespaceOnly`` Helm value.
You can confirm the result with the following command:

.. code-block:: shell-session

    $ kubectl get configmaps -n kube-system cilium-config -oyaml | grep bpf-lb-sock-hostns
    bpf-lb-sock-hostns-only: "true"

.. _gsg_istio_cnp:

Istio configuration
===============================

When you deploy Istio, be aware of:

* The new experimental `ambient mesh <https://istio.io/latest/blog/2022/introducing-ambient-mesh/>`_ 
  data plane is not supported, as it interferes with the Cilium data plane.

* mTLS mode ``STRICT`` or ``PERMISSIVE`` (default) are not compatible with Cilium HTTP network policy. 
  To use an HTTP-based network policy (for example, :ref:`l7_policy`), 
  you must configure ``mtls.mode=DISABLE`` under Istio's ``PeerAuthentication``.

* When using Kubernetes admission webhooks to `inject sidecar proxies <https://istio.io/latest/docs/ops/configuration/mesh/webhook/>`_
  together with Cilium overlay mode (VXLAN or GENEVE), ``istiod`` pods must be running with ``hostNetwork: true`` in order to be reachable 
  by the API server.

Demo Application
===============================

The following guide demonstrates the interaction between Istio's ``mTLS`` mode and 
Cilium network policies, including the caveat described in the :ref:`gsg_istio_cnp` section.

Prerequisites
^^^^^^^^^^^^^

* Istio is already installed on the local Kubernetes cluster.
* Cilium is already installed with the ``socketLB.hostNamespaceOnly`` Helm value.
* Istio's ``istioctl`` is installed on the local host.

Start by deploying a set of web servers and client applications across three different namespaces:

.. parsed-literal::

    kubectl create ns red
    kubectl -n red apply -f <(curl -s \ |SCM_WEB|\/examples/kubernetes-istio/httpbin.yaml | istioctl kube-inject -f -)
    kubectl -n red apply -f <(curl -s \ |SCM_WEB|\/examples/kubernetes-istio/netshoot.yaml | istioctl kube-inject -f -)
    kubectl create ns blue
    kubectl -n blue apply -f <(curl -s \ |SCM_WEB|\/examples/kubernetes-istio/httpbin.yaml | istioctl kube-inject -f -)
    kubectl -n blue apply -f <(curl -s \ |SCM_WEB|\/examples/kubernetes-istio/netshoot.yaml | istioctl kube-inject -f -)
    kubectl create ns green
    kubectl -n green apply -f \ |SCM_WEB|\/examples/kubernetes-istio/netshoot.yaml

By default, Istio works in ``PERMISSIVE`` mode, allowing both Istio-managed and Pods without sidecars
to send and receive traffic between each other. You can test the connectivity between client and server applications 
deployed in the preceding example by entering the following commands:

.. code-block:: shell-session

    kubectl exec -n red deploy/netshoot -- curl http://httpbin.red/ip -s -o /dev/null -m 1 -w "client 'red' to server 'red': %{http_code}\n"
    kubectl exec -n blue deploy/netshoot -- curl http://httpbin.red/ip -s -o /dev/null -m 1 -w "client 'blue' to server 'red': %{http_code}\n"
    kubectl exec -n green deploy/netshoot -- curl http://httpbin.red/ip -s -o /dev/null -m 1 -w "client 'green' to server 'red': %{http_code}\n"
    kubectl exec -n red deploy/netshoot -- curl http://httpbin.blue/ip -s -o /dev/null -m 1 -w "client 'red' to server 'blue': %{http_code}\n"
    kubectl exec -n blue deploy/netshoot -- curl http://httpbin.blue/ip -s -o /dev/null -m 1 -w "client 'blue' to server 'blue': %{http_code}\n"
    kubectl exec -n green deploy/netshoot -- curl http://httpbin.blue/ip -s -o /dev/null -m 1 -w "client 'green' to server 'blue': %{http_code}\n"

All commands should complete successfully:

.. code-block:: shell-session

    client 'red' to server 'red': 200
    client 'blue' to server 'red': 200
    client 'green' to server 'red': 200
    client 'red' to server 'blue': 200
    client 'blue' to server 'blue': 200
    client 'green' to server 'blue': 200

You can apply network policies to restrict communication between namespaces. 
The following command applies an L4 network policy that restricts communication 
in the ``blue`` namespace to clients located only in ``blue`` and ``red`` namespaces.

.. parsed-literal::
    kubectl -n blue apply -f \ |SCM_WEB|\/examples/kubernetes-istio/l4-policy.yaml

Re-run the same connectivity checks to confirm the expected result:

.. code-block:: shell-session

    client 'red' to server 'red': 200
    client 'blue' to server 'red': 200
    client 'green' to server 'red': 200
    client 'red' to server 'blue': 200
    client 'blue' to server 'blue': 200
    client 'green' to server 'blue': 000
    command terminated with exit code 28

You can then decide to enhance the same network policy to perform additional HTTP-based checks. 
The following command applies the L7 network policy allowing communication only with the ``/ip`` URL path:

.. parsed-literal::
    kubectl -n blue apply -f \ |SCM_WEB|\/examples/kubernetes-istio/l7-policy.yaml

At this point, all communication with the ``blue`` namespace is broken since the Cilium proxy (HTTP) interferes with
Istio's mTLS-based HTTPs connections:

.. code-block:: shell-session

    client 'red' to server 'red': 200
    client 'blue' to server 'red': 200
    client 'green' to server 'red': 200
    client 'red' to server 'blue': 503
    client 'blue' to server 'blue': 503
    client 'green' to server 'blue': 000
    command terminated with exit code 28

To solve the problem, you can disable Istio's mTLS authentication by configuring a new policy:

.. literalinclude:: ../../../examples/kubernetes-istio/authn.yaml

You must apply this policy to the same namespace where you implement the HTTP-based network policy:

.. parsed-literal::
    kubectl -n blue apply -f \ |SCM_WEB|\/examples/kubernetes-istio/authn.yaml

Re-run a connectivity check to confirm that communication with the ``blue`` namespaces has been restored. 
You can verify that Cilium is enforcing the L7 network policy by accessing a different URL path, for example ``/deny``:

.. code-block:: shell-session

    $ kubectl exec -n red deploy/netshoot -- curl http://httpbin.blue/deny -s -o /dev/null -m 1 -w "client 'red' to server 'blue': %{http_code}\n"
    client 'red' to server 'blue': 403







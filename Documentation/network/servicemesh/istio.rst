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
Istio's `sidecar proxies (sidecar mode) <https://istio.io/latest/docs/ops/deployment/architecture/>`_  or `node proxy (ambient mode) <https://istio.io/latest/docs/ops/ambient/architecture/>`_
is not disrupted. Disruptions can happen when you enable Cilium's ``kubeProxyReplacement`` feature  (see :ref:`kubeproxy-free` docs),
which enables socket based load balancing inside a Pod.


To ensure that Cilium does not interfere with Istio, it is important to set the
``bpf-lb-sock-hostns-only`` parameter in the Cilium ConfigMap to ``true``. This can be achieved by using the
``--set`` flag with the ``socketLB.hostNamespaceOnly`` Helm value set to ``true``.
You can confirm the result with the following command:

.. code-block:: shell-session

    $ kubectl get configmaps -n kube-system cilium-config -oyaml | grep bpf-lb-sock-hostns
    bpf-lb-sock-hostns-only: "true"


Istio uses a CNI plugin to implement functionality for both sidecar and ambient modes.
To ensure that Cilium does not interfere with other CNI plugins on the node, it is important to set the ``cni-exclusive``
parameter in the Cilium ConfigMap to ``false``. This can be achieved by using the ``--set`` flag with the ``cni.exclusive``
Helm value set to ``false``.
You can confirm the result with the following command:

.. code-block:: shell-session

    $ kubectl get configmaps -n kube-system cilium-config -oyaml | grep cni-exclusive
    cni-exclusive: "false"

.. _gsg_istio_cnp:

Istio configuration
===============================

When you deploy Cilium and Istio together, be aware of:

* Either Cilium or Istio L7 HTTP policy controls can be used, but it is not recommended to use **both** Cilium and Istio L7 HTTP policy
  controls at the same time, to avoid split-brain problems.

  In order to use Cilium L7 HTTP policy controls (for example, :ref:`l7_policy`) with Istio (sidecar or ambient modes), you must:

  - Sidecar: Disable Istio mTLS for the workloads you wish to manage with Cilium L7 policy by configuring
    ``mtls.mode=DISABLE`` under Istio's `PeerAuthentication <https://istio.io/latest/docs/reference/config/security/peer_authentication/#PeerAuthentication>`_.

  - Ambient: Remove the workloads you wish to manage with Cilium L7 policy from Istio ambient by removing either the
    ``istio.io/dataplane-mode`` label from the namespace,
    or annotating the pods you wish to manage with Cilium L7 with ``ambient.istio.io/redirection: disabled``.

  as otherwise the traffic between Istio-managed workloads will be encrypted by Istio with mTLS, and not accessible to Cilium for the purposes of L7 policy enforcement.

  If using Istio L7 HTTP policy controls, policy will be managed in Istio and disabling mTLS between workloads is not required.

* If using Istio mTLS in ambient mode with Istio L7 HTTP policy controls, traffic between ambient workloads will be
  `encrypted and tunneled in and out of the pods by Istio over port 15008 <https://istio.io/latest/docs/ops/ambient/usage/traffic-redirection/>`_.
  In this scenario, Cilium NetworkPolicy will still apply to the encrypted and tunneled L4 traffic entering and leaving the Istio-managed pods,
  but Cilium will have no visibility into the actual source and destination of that tunneled and encrypted L4 traffic, or any L7 information.
  This means that Istio should be used to enforce policy for traffic between Istio-managed, mTLS-secured workloads at L4 or above.
  Traffic ingressing to Istio-managed workloads from non-Istio-managed workloads will continue to be fully subjected to Cilium-enforced Kubernetes NetworkPolicy,
  as it would not be tunneled or encrypted.

* When using Istio in sidecar mode with `automatic sidecar injection <https://istio.io/latest/docs/setup/additional-setup/sidecar-injection/#automatic-sidecar-injection>`_,
  together with Cilium overlay mode (VXLAN or GENEVE), ``istiod`` pods must be running with ``hostNetwork: true`` in order to be reachable by the API server.

Demo Application (Using Cilium with Istio ambient mode)
=======================================================

The following guide demonstrates the interaction between Istio's ambient ``mTLS`` mode and
Cilium network policies when using Cilium L7 HTTP policy controls instead of Istio L7 HTTP policy controls, including the caveat described in the :ref:`gsg_istio_cnp` section.

Prerequisites
^^^^^^^^^^^^^

* Istio is already installed on the local Kubernetes cluster.
* Cilium is already installed with the ``socketLB.hostNamespaceOnly`` and ``cni.exclusive=false`` Helm values.
* Istio's ``istioctl`` is installed on the local host.

Start by deploying a set of web servers and client applications across three different namespaces:

.. parsed-literal::

    kubectl create ns red
    kubectl label namespace red istio.io/dataplane-mode=ambient
    kubectl -n red apply -f <(curl -s \ |SCM_WEB|\/examples/kubernetes-istio/httpbin.yaml)
    kubectl -n red apply -f <(curl -s \ |SCM_WEB|\/examples/kubernetes-istio/netshoot.yaml)
    kubectl create ns blue
    kubectl label namespace blue istio.io/dataplane-mode=ambient
    kubectl -n blue apply -f <(curl -s \ |SCM_WEB|\/examples/kubernetes-istio/httpbin.yaml)
    kubectl -n blue apply -f <(curl -s \ |SCM_WEB|\/examples/kubernetes-istio/netshoot.yaml)
    kubectl create ns green
    kubectl -n green apply -f \ |SCM_WEB|\/examples/kubernetes-istio/netshoot.yaml

By default, Istio works in ``PERMISSIVE`` mode, allowing both Istio-ambient-managed and Istio-unmanaged pods
to send and receive unsecured traffic between each other. You can test the connectivity between client and server applications deployed in the preceding example by entering the following commands:

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

You can apply Cilium-enforced L4 NetworkPolicy to restrict communication between namespaces.
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
The following command applies a Cilium L7 network policy allowing communication only with the ``/ip`` URL path:

.. parsed-literal::
    kubectl -n blue apply -f \ |SCM_WEB|\/examples/kubernetes-istio/l7-policy.yaml

At this point, all communication with the ``blue`` namespace is broken since the Cilium proxy (HTTP) interferes with Istio's mTLS-based HTTPS connections:

.. code-block:: shell-session

    client 'red' to server 'red': 200
    client 'blue' to server 'red': 200
    client 'green' to server 'red': 200
    client 'red' to server 'blue': 000
    command terminated with exit code 28
    client 'blue' to server 'blue': 000
    command terminated with exit code 28
    client 'green' to server 'blue': 000
    command terminated with exit code 28

To solve the problem and allow Cilium to manage L7 policy, you must remove the workloads or namespaces
you want Cilium to manage L7 policy for from the Istio ambient mesh:

.. parsed-literal::

    kubectl label namespace red istio.io/dataplane-mode-
    kubectl label namespace blue istio.io/dataplane-mode-

Re-run a connectivity check to confirm that communication with the ``blue`` namespaces has been restored.
You can verify that Cilium is enforcing the L7 network policy by accessing a different URL path, for example ``/deny``:

.. code-block:: shell-session

    $ kubectl exec -n red deploy/netshoot -- curl http://httpbin.blue/deny -s -o /dev/null -m 1 -w "client 'red' to server 'blue': %{http_code}\n"
    client 'red' to server 'blue': 403

Demo Application (Istio sidecar mode)
=====================================

The following guide demonstrates the interaction between Istio's sidecar-based ``mTLS`` mode and
Cilium network policies when using Cilium L7 HTTP policy controls instead of Istio L7 HTTP policy controls, including the caveat described in the :ref:`gsg_istio_cnp` section around disabling ``mTLS``

Prerequisites
^^^^^^^^^^^^^

* Istio is already installed on the local Kubernetes cluster.
* Cilium is already installed with the ``socketLB.hostNamespaceOnly`` and ``cni.exclusive=false`` Helm values.
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
The following command applies a Cilium-managed L4 network policy that restricts communication
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

You can then decide to enhance the L4 network policy to perform additional Cilium-managed HTTP-based checks.
The following command applies Cilium L7 network policy allowing communication only with the ``/ip`` URL path:

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

To solve the problem and allow Cilium to manage L7 policy, you must disable Istio's mTLS authentication by configuring a new policy:

.. literalinclude:: ../../../examples/kubernetes-istio/authn.yaml
     :language: yaml

You must apply this policy to the same namespace where you implement the HTTP-based network policy:

.. parsed-literal::
    kubectl -n blue apply -f \ |SCM_WEB|\/examples/kubernetes-istio/authn.yaml

Re-run a connectivity check to confirm that communication with the ``blue`` namespaces has been restored. 
You can verify that Cilium is enforcing the L7 network policy by accessing a different URL path, for example ``/deny``:

.. code-block:: shell-session

    $ kubectl exec -n red deploy/netshoot -- curl http://httpbin.blue/deny -s -o /dev/null -m 1 -w "client 'red' to server 'blue': %{http_code}\n"
    client 'red' to server 'blue': 403

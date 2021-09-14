.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _egress-gateway:

**********************
Egress Gateway (beta)
**********************

.. include:: ../beta.rst

.. note::

   Egress Gateway requires a 5.2 or more recent kernel.

The egress gateway allows users to redirect egress pod traffic through
specific, gateway nodes. Packets are masqueraded to the gateway node IP.

This document explains how to enable the egress gateway and configure
egress NAT policies to route and SNAT the egress traffic for a specific
workload.

.. note::

   This guide assumes that Cilium has been correctly installed in your
   Kubernetes cluster. Please see :ref:`k8s_quick_install` for more
   information. If unsure, run ``cilium status`` and validate that Cilium is up
   and running.

Enable Egress Gateway
=====================

The feature is disabled by default. The egress gateway requires BPF
masquerading, which itself requires BPF NodePort to be enabled. An easy way to
enable all requirements is as follows.

.. tabs::

    .. group-tab:: Helm

        If you installed Cilium via ``helm install``, you may enable
        the Egress gateway feature with the following command:

        .. parsed-literal::

           helm upgrade cilium |CHART_RELEASE| \\
              --namespace kube-system \\
              --reuse-values \\
              --set egressGateway.enabled=true \\
              --set bpf.masquerade=true \\
              --set kubeProxyReplacement=strict

    .. group-tab:: ConfigMap

       Egress Gateway support can be enabled by setting the following options
       in the ``cilium-config`` ConfigMap:

       .. code-block:: shell-session

          enable-egress-gateway: true
          enable-bpf-masquerade: true
          kube-proxy-replacement: strict

Create an External Service (Optional)
=====================================

This feature will change the default behavior how a packet leaves a cluster. As a
result, from the external service's point of view, it will see different source IP
address from the cluster. If you don't have an external service to experiment with,
nginx is a very simple example that can demonstrate the functionality, while nginx's
access log shows which IP address the request is coming from.

Create an nginx service on a Linux node that is external to the existing Kubernetes
cluster, and use it as the destination of the egress traffic.

.. code-block:: shell-session

    $ # Install and start nginx
    $ sudo apt install nginx
    $ sudo systemctl start nginx

    $ # Make sure the service is started and listens on port :80
    $ sudo systemctl status nginx
    ● nginx.service - A high performance web server and a reverse proxy server
    Loaded: loaded (/lib/systemd/system/nginx.service; enabled; vendor preset: enabled)
    Active: active (running) since Sun 2021-04-04 21:58:57 UTC; 1min 3s ago
    [...]
    $ curl http://192.168.33.13:80  # Assume 192.168.33.13 is the external IP of the node
    [...]
    <title>Welcome to nginx!</title>
    [...]

Create Client Pods
==================

Deploy a client pod that will generate traffic which will be redirected based on
the configurations specified in the CiliumEgressNATPolicy.

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-sw-app.yaml
    $ kubectl get po
    NAME                             READY   STATUS    RESTARTS   AGE
    pod/mediabot                     1/1     Running   0          14s

    $ kubectl exec mediabot -- curl http://192.168.33.13:80
    <HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
    [...]

Verify access log from nginx node or other external services that the request is coming
from one of the node in Kubernetes cluster. For example, in nginx node, the access log
will contain something like the following:

.. code-block:: shell-session

    $ tail /var/log/nginx/access.log
    [...]
    192.168.33.11 - - [04/Apr/2021:22:06:57 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.52.1"

In the previous example, the client pod is running on the node ``192.168.33.11``, so the result makes sense.
This is the default Kubernetes behavior without egress NAT.

Configure Egress IPs
====================

Deploy the following deployment to assign additional egress IP to the gateway node. The node that runs the
pod will have additional IP addresses configured on the external interface (``enp0s8`` as in the example),
and become the egress gateway. In the following example, ``192.168.33.100`` and ``192.168.33.101`` becomes
the egress IP which can be consumed by Egress NAT Policy. Please make sure these IP addresses are routable
on the interface they are assigned to, otherwise the return traffic won't be able to route back.

.. literalinclude:: ../../examples/kubernetes-egress-gateway/egress-ip-deployment.yaml

Create Egress NAT Policy
========================

Apply the following Egress NAT Policy, which basically means: when the pod is running in the namespace
``default`` and the pod itself has label ``org: empire`` and ``class: mediabot``, if it's trying to talk to
IP CIDR ``192.168.33.13/32``, then use egress IP ``192.168.33.100``. In this example, it tells Cilium to
forward the packet from client pod to the gateway node with egress IP ``192.168.33.100``, and masquerade
with that IP address.

.. literalinclude:: ../../examples/kubernetes-egress-gateway/egress-nat-policy.yaml

Let's switch back to the client pod and verify it works.

.. code-block:: shell-session

    $ kubectl exec mediabot -- curl http://192.168.33.13:80
    <HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
    [...]

Verify access log from nginx node or service of your chose that the request is coming from egress IP now 
instead of one of the nodes in Kubernetes cluster. In the nginx's case, you will see logs like the
following shows that the request is coming from ``192.168.33.100`` now, instead of ``192.168.33.11``.

.. code-block:: shell-session

    $ tail /var/log/nginx/access.log
    [...]
    192.168.33.100 - - [04/Apr/2021:22:06:57 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.52.1"


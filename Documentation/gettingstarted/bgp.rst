.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bgp:

**********
BGP (beta)
**********

BGP provides a way to advertise routes using traditional networking protocols
to allow Cilium-managed services to be accessible outside the cluster.

This document explains how to configure Cilium's native support for announcing
``LoadBalancer`` IPs of ``Services`` and a Kubernetes node's Pod CIDR range via BGP. 
It leverages `MetalLB's <https://metallb.universe.tf/>`_ simple and effective 
implementation of IP allocation and the minimal BGP protocol support to do this. 
The configuration for Cilium is the same as MetalLB's configuration.

Specifically, if a ``Service`` of type ``LoadBalancer`` is created, Cilium will
allocate an IP for it from a specified pool. Once the IP is allocated, the
Agents will announce via BGP depending on the ``Service``'s
``ExternalTrafficPolicy``. See MetalLB's `documentation
<https://metallb.universe.tf/usage/#bgp>`_ on this specific topic.

.. include:: ../beta.rst

Deploy Cilium
=============

.. include:: k8s-install-download-release.rst

BGP support is enabled by providing the BGP configuration via a ConfigMap and
by setting a few Helm values. Otherwise, BGP is disabled by default.

Here's an example ConfigMap:

.. code-block:: yaml

   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: bgp-config
     namespace: kube-system
   data:
     config.yaml: |
       peers:
         - peer-address: 10.0.0.1
           peer-asn: 64512
           my-asn: 64512
       address-pools:
         - name: default
           protocol: bgp
           addresses:
             - 192.0.2.0/24

Here are the required Helm values:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set bgp.enabled=true \\
     --set bgp.announce.loadbalancerIP=true
     --set bgp.announce.podCIDR=true

At least one ``bgp.announce.*`` value is required if ``bgp.enabled=true`` is set.

Verify that Cilium Agent pod is running.

.. code-block:: shell-session

   $ kubectl -n kube-system get pods -l k8s-app=cilium
   NAME           READY   STATUS    RESTARTS   AGE
   cilium-5ngzd   1/1     Running   0          3m19s

Create LoadBalancer and backend pods
====================================

Apply the following ``LoadBalancer`` ``Service`` and its corresponding
backends:

.. code-block:: yaml

   apiVersion: v1
   kind: Service
   metadata:
     name: test-lb
   spec:
     type: LoadBalancer
     ports:
     - port: 80
       targetPort: 80
       protocol: TCP
       name: http
     selector:
       svc: test-lb
   ---
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: nginx
   spec:
     selector:
       matchLabels:
         svc: test-lb
     template:
       metadata:
         labels:
           svc: test-lb
       spec:
         containers:
         - name: web
           image: nginx
           imagePullPolicy: IfNotPresent
           ports:
           - containerPort: 80
           readinessProbe:
             httpGet:
               path: /
               port: 80

Observe that the Operator allocates an external IP for ``test-lb``:

.. code-block:: shell-session

   $ kubectl get svc
   NAME        TYPE          CLUSTER-IP  EXTERNAL-IP  PORT(S)       AGE
   kubernetes  ClusterIP     172.20.0.1  <none>       443/TCP       4d23h
   test-lb     LoadBalancer  172.20.0.5  192.0.2.154  80:30724/TCP  10s

Verify that the backend is running:

.. code-block:: shell-session

   $ kubectl get pods | grep nginx
   nginx                      1/1     Running   0          16s

Validate BGP announcements
==========================

To see whether Cilium is announcing the external IP of the ``Service`` or the Pod CIDR range of your
Kubernetes nodes, check the node's routing table that's running your BGP router. 

Alternatively, you can run ``tcpdump`` inside the Cilium pod (it'll need to be
``apt install``'d) to see BGP messages like so:

.. code-block:: shell-session

   root@kind-worker:/home/cilium# tcpdump -n -i any tcp port 179
   tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
   listening on any, link-type LINUX_SLL (Linux cooked v1), capture size 262144 bytes
   17:03:19.380682 IP 172.20.0.2.43261 > 10.0.0.1.179: Flags [P.], seq 2930402899:2930402918, ack 2731344744, win 502, options [nop,nop,TS val 4080796863 ecr 4108836857], length 19: BGP
   17:03:19.385065 IP 10.0.0.1.179 > 172.20.0.2.43261: Flags [P.], seq 1:20, ack 19, win 509, options [nop,nop,TS val 4108866857 ecr 4080796863], length 19: BGP

Verify that traffic to the external IP is directed to the backends:

.. code-block:: shell-session

   $ # Exec / SSH into BGP router
   $ curl 192.0.2.154

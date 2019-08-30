.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _nodeport:

**************************
Kubernetes NodePort (beta)
**************************

This guide explains how to configure Cilium to enable Kubernetes NodePort
services in BPF which can replace NodePort implemented by ``kube-proxy``.
Enabling the feature allows to run a fully functioning Kubernetes cluster
without ``kube-proxy``.

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue if
    you experience any problems.

.. note::

   NodePort services depend on the :ref:`host-services` feature, therefore
   a v4.19.57, v5.1.16, v5.2.0 or more recent Linux kernel is required. Note
   that v5.0.y kernels do not have the fix required to run BPF NodePort since
   at this point in time the v5.0.y stable kernel is end-of-life (EOL) and
   not maintained anymore.

.. include:: k8s-install-download-release.rst

Generate the required YAML file and deploy it:

.. code:: bash

   helm template cilium \
     --namespace kube-system \
     --set global.nodePort.enabled=true \
     > cilium.yaml

By default, a NodePort service will be accessible via an IP address of a native
device which has a default route on the host. To change a device, set its name
in the ``global.nodePort.device`` option.

In addition, thanks to the :ref:`host-services` feature, the NodePort service
can be accessed from a host or a Pod within a cluster via it's public,
cilium_host device or loopback address, e.g. ``127.0.0.1:$NODE_PORT``.

Cilium's BPF-based NodePort implementation is supported in direct routing as
well as in tunneling mode.

If ``kube-apiserver`` was configured to use a non-default NodePort port range,
then the same range must be passed to Cilium via the ``global.nodePort.range``
option.

Once configured, apply the DaemonSet file to deploy Cilium and verify that it
has come up correctly:

.. parsed-literal::

    kubectl create -f cilium.yaml
    kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m

Limitations
###########

    * Both Service's ``externalTrafficPolicy: Local`` and ``healthCheckNodePort``
      are currently not supported.
    * NodePort services are currently exposed through the native device which has
      the default route on the host or a user specified device. In tunneling mode,
      they are additionally exposed through the tunnel interface (``cilium_vxlan``
      or ``cilium_geneve``). Exposing services through multiple native devices
      will be supported in upcoming Cilium versions.

.. _external-ips:

*****************************
Kubernetes externalIPs (beta)
*****************************

By default, an ``externalIPs`` service will be accessible via the device which
has a default route on the host. To change a device, set its name in the
``global.nodePort.device`` option.

In addition, thanks to the :ref:`host-services` feature, the ExternalIP service
can be accessed from outside the node, i.e., traffic that ingresses into
the cluster with the external IP (as destination IP), on the Service port,
will be routed to one of the Service endpoints. ``externalIPs`` are not managed
by Kubernetes and are the responsibility of the cluster administrator.

If a service is defined with a ``externalIPs`` that belongs to the host where
the service translation is being performed, the service translation is executed.
In other words, if a pod tries to connect to an ``externalIP`` that does not
belong to the host where it is hosted, the service translation does not occur
and the traffic is sent to the external IP address without any service
translation.

Once configured, apply the DaemonSet file to deploy Cilium and verify that it
has come up correctly:

.. parsed-literal::

    kubectl create -f cilium.yaml
    kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m

To try it out you can disable kube-proxy in your cluster and run, as a testing
example, the following demo in your k8s cluster.

.. literalinclude:: ../../examples/kubernetes-external-ips/demo.yaml

After deploying the following manifest you can verify it if it's being routed
by Cilium by checking ``cilium service list``:

.. parsed-literal::
    $ kubectl exec -ti cilium-crf7f -- cilium service list
    ID   Frontend              Service Type   Backend
    22   192.0.2.233:82        ExternalIPs    1 => 10.16.92.10:80
                                              2 => 10.16.56.85:80


You can then run the following command **outside** the node where the service is
deployed to see the routing being performed correctly:

.. parsed-literal::

    $ # add a route for the external service IP
    $ ip r a 192.0.2.233 via <node-ip>
    $ curl 192.0.2.233:82
    <html><body><h1>It works!</h1></body></html>

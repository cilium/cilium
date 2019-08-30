.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _external-ips:

*****************************
Kubernetes externalIPs (beta)
*****************************

This guide explains how to configure Cilium to enable Kubernetes ExternalIPs
services in BPF which can replace ``externalIPs`` implemented by ``kube-proxy``.
Enabling the feature allows to run a fully functioning Kubernetes cluster
without ``kube-proxy``.

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue if
    you experience any problems.

.. note::

   ExternalIPs services depend on the :ref:`host-services` feature, therefore
   a v4.19.57, v5.1.16, v5.2.0 or more recent Linux kernel is required.

.. include:: k8s-install-download-release.rst

Generate the required YAML file and deploy it:

.. code:: bash

   helm template cilium \
     --namespace kube-system \
     --set global.nodePort.enabled=true \
     > cilium.yaml

By default, an ``externalIPs`` service will be accessible via the device which has a
default route on the host. To change a device, set its name in the
``global.nodePort.device`` option.

In addition, thanks to the :ref:`host-services` feature, the ExternalIP service
can only be accessed from outside the node, i.e., traffic that ingresses into
the cluster with the external IP (as destination IP), on the Service port,
will be routed to one of the Service endpoints. ``externalIPs`` are not managed
by Kubernetes and are the responsibility of the cluster administrator.

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
    ID   Frontend              External IP   Backend
    22   192.0.2.233:82        true          1 => 10.16.92.10:80
                                             2 => 10.16.56.85:80


You can then run the following command **outside** the node where the service is
deployed to see the routing being performed correctly:

.. parsed-literal::

    $ # add a route for the external service IP
    $ ip r a 192.0.2.233 via <node-ip>
    $ curl 192.0.2.233:82
    <html><body><h1>It works!</h1></body></html>

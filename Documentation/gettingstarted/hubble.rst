.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _hubble_gsg:

*************************************************
Networking and security observability with Hubble
*************************************************

This guide provides a walkthrough of setting up a local multi-node Kubernetes
cluster on Docker using `kind <https://kind.sigs.k8s.io/>`_ in order to
demonstrate some of Hubble's capabilities.

If you haven't read the :ref:`intro` yet, we'd encourage you to do that first.

The best way to get help if you get stuck is to ask a question on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_.  With Cilium contributors
across the globe, there is almost always someone available to help.

.. include:: kind-install.rst

.. note::
   The cluster nodes will remain in state ``NotReady`` until Cilium is deployed.
   This behavior is expected.

Deploy Cilium and Hubble
========================

.. include:: k8s-install-download-release.rst

Pre-load images into the kind cluster so each node does not have to pull
them:

.. parsed-literal::

  docker pull cilium/cilium:|IMAGE_TAG|
  kind load docker-image cilium/cilium:|IMAGE_TAG|

Install Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set global.nodeinit.enabled=true \\
      --set global.kubeProxyReplacement=partial \\
      --set global.hostServices.enabled=false \\
      --set global.externalIPs.enabled=true \\
      --set global.nodePort.enabled=true \\
      --set global.hostPort.enabled=true \\
      --set global.pullPolicy=IfNotPresent \\
      --set global.hubble.enabled=true \\
      --set global.hubble.listenAddress=":4244" \\
      --set global.hubble.relay.enabled=true \\
      --set global.hubble.ui.enabled=true

Validate the Installation
=========================

You can monitor as Cilium and all required components are being installed:

.. parsed-literal::

    kubectl -n kube-system get pods --watch
    NAME                                         READY   STATUS              RESTARTS   AGE
    cilium-2rlwx                                 0/1     Init:0/2            0          2s
    cilium-ncqtb                                 0/1     Init:0/2            0          2s
    cilium-node-init-9h9dd                       0/1     ContainerCreating   0          2s
    cilium-node-init-cmks4                       0/1     ContainerCreating   0          2s
    cilium-node-init-vnx5n                       0/1     ContainerCreating   0          2s
    cilium-node-init-zhs66                       0/1     ContainerCreating   0          2s
    cilium-nrzsp                                 0/1     Init:0/2            0          2s
    cilium-operator-599dbcf854-7w4rr             0/1     Pending             0          2s
    cilium-pghbg                                 0/1     Init:0/2            0          2s
    coredns-66bff467f8-gnzk7                     0/1     Pending             0          6m6s
    coredns-66bff467f8-wzh49                     0/1     Pending             0          6m6s
    etcd-kind-control-plane                      1/1     Running             0          6m15s
    hubble-relay-5684848cc8-6ldhj                0/1     ContainerCreating   0          2s
    hubble-ui-54c6bc4cdc-h5drq                   0/1     Pending             0          2s
    kube-apiserver-kind-control-plane            1/1     Running             0          6m15s
    kube-controller-manager-kind-control-plane   1/1     Running             0          6m15s
    kube-proxy-dchqv                             1/1     Running             0          5m51s
    kube-proxy-jkvhr                             1/1     Running             0          5m53s
    kube-proxy-nb9b2                             1/1     Running             0          6m5s
    kube-proxy-ttf7z                             1/1     Running             0          5m50s
    kube-scheduler-kind-control-plane            1/1     Running             0          6m15s
    cilium-node-init-zhs66                       1/1     Running             0          4s

It may take a couple of minutes for all components to come up:

.. parsed-literal::

    kubectl -n kube-system get pods
    NAME                                         READY   STATUS    RESTARTS   AGE
    cilium-2rlwx                                 1/1     Running   0          16m
    cilium-ncqtb                                 1/1     Running   0          16m
    cilium-node-init-9h9dd                       1/1     Running   1          16m
    cilium-node-init-cmks4                       1/1     Running   1          16m
    cilium-node-init-vnx5n                       1/1     Running   1          16m
    cilium-node-init-zhs66                       1/1     Running   1          16m
    cilium-nrzsp                                 1/1     Running   0          16m
    cilium-operator-599dbcf854-7w4rr             1/1     Running   0          16m
    cilium-pghbg                                 1/1     Running   0          16m
    coredns-66bff467f8-gnzk7                     1/1     Running   0          22m
    coredns-66bff467f8-wzh49                     1/1     Running   0          22m
    etcd-kind-control-plane                      1/1     Running   0          22m
    hubble-relay-5684848cc8-2z6qk                1/1     Running   0          21s
    hubble-ui-54c6bc4cdc-g5mgd                   1/1     Running   0          17s
    kube-apiserver-kind-control-plane            1/1     Running   0          22m
    kube-controller-manager-kind-control-plane   1/1     Running   0          22m
    kube-proxy-dchqv                             1/1     Running   0          21m
    kube-proxy-jkvhr                             1/1     Running   0          21m
    kube-proxy-nb9b2                             1/1     Running   0          22m
    kube-proxy-ttf7z                             1/1     Running   0          21m
    kube-scheduler-kind-control-plane            1/1     Running   0          22m

Install Hubble CLI
==================
.. include:: hubble-install.rst

Port Forward
============

.. parsed-literal::
   kubectl port-forward -n kube-system svc/hubble-relay 4245:80
   kubectl port-forward -n kube-system svc/hubble-ui 12000:80

.. parsed-literal::
   hubble observe --last 1 -o json --debug --server localhost:4245

Open http://localhost:12000/ from a browser.

Cleanup
=======

Once you are done experimenting with Hubble, you can remove all traces of the cluster by running the following command:


.. parsed-literal::
   kind delete cluster

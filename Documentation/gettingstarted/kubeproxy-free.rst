.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _kubeproxy-free:

************************************
Kubernetes without kube-proxy (beta)
************************************

This guide explains how to provision a Kubernetes cluster without
``kube-proxy``, and to use Cilium to replace it. For simplicity,
we will use ``kubeadm`` to bootstrap the cluster.

For installing ``kubeadm`` and for more provisioning options please refer to
`the official kubeadm documentation <https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm>`__.

Initialize the control-plane node:

.. code:: bash

    kubeadm init --pod-network-cidr=10.217.0.0/16

.. note::

    Currently, it is not possible to disable kube-proxy via ``--skip-phases=addon/kube-proxy``
    due to the bug `kubeadm#1733 <https://github.com/kubernetes/kubeadm/issues/1733>`__.

    Once it has been resolved, the workaround below for manually removing the
    ``kube-proxy`` DaemonSet and iptables-save/restore cleaning is no longer needed
    and initialization would look like:
    ``kubeadm init --pod-network-cidr=10.217.0.0/16 --skip-phases=addon/kube-proxy``

Next, delete the ``kube-proxy`` DaemonSet and remove its iptables rules:

.. code:: bash

   kubectl -n kube-system delete ds kube-proxy
   iptables-restore <(iptables-save | grep -v KUBE)

Afterwards, join worker nodes by specifying the control-plane node IP address
and the token returned by ``kubeadm init``:

.. code:: bash

   kubectl join <..>

Download the Cilium release tarball and change to the Kubernetes
install directory:

.. code:: bash

    curl -LO https://github.com/cilium/cilium/archive/v1.6.tar.gz
    tar xzvf v1.6.tar.gz
    cd cilium-1.6/install/kubernetes

`Install Helm <https://helm.sh/docs/using_helm/#install-helm>`__ to prepare generating
the deployment artifacts based on the Helm templates.

Next, generate the required YAML files and deploy them. Replace ``$API_SERVER_IP``
and ``$API_SERVER_PORT`` with the control-plane node IP address and the kube-apiserver
port number reported by ``kubeadm init`` (usually it is ``6443``).

.. code:: bash

    helm template cilium \
        --namespace kube-system \
        --set global.nodePort.enabled=true \
        --set global.k8sServiceHost=$API_SERVER_IP \
        --set global.k8sServicePort=$API_SERVER_PORT \
        --set global.tag=v1.6.0 \
    > cilium.yaml
    kubectl apply -f cilium.yaml

This will install Cilium as a CNI plugin with the BPF kube-proxy replacement.
See :ref:`nodeport` for requirements and configuration options for NodePort
services.

.. note::

   Currently, in the kube-proxy-free setup, Cilium will connect to only one
   kube-apiserver specified by ``k8sServiceHost:k8sServicePort``. This is not
   ideal in a multi-control-plane node setup. The upcoming Cilium release will
   allow to connect to multiple nodes (`GH#9018 <https://github.com/cilium/cilium/issues/9018>`__).

Finally, verify that Cilium has come up correctly on all nodes:

.. parsed-literal::

    kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m
    cilium-mkcmb        1/1       Running   0          10m

.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _kubeproxy-free:

************************************
Kubernetes without kube-proxy (beta)
************************************

This guide explains how to provision a Kubernetes cluster without
``kube-proxy``, and to use Cilium to replace it. For the simplicity
reason we will use ``kubeadm`` to bootstrap the cluster.

For installing ``kubeadm`` and for more provisioning options please refer to
`the official kubeadm documentation <https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm>`__.

First of all, initialize the control-plane node:

.. code:: bash

    kubeadm init --pod-network-cidr=10.217.0.0/16

Next, delete ``kube-proxy`` DaemonSet and remove its iptables rules:

.. code:: bash

   kubectl -n kube-system delete ds kube-proxy
   iptables-restore <(iptables-save | grep -v KUBE)

Afterwards, join worker nodes with specifying the control-plane node IP address
and the token returned by ``kubeadm init``:

.. code:: bash

   kubectl join <..>

Next, distribute the Kubernetes configuration file (``/etc/kubernetes/admin.conf``)
from the control-plane node to all worker nodes, and store it at the same path
on all nodes.

Later on, download the Cilium release tarball and change to the kubernetes
install directory:

.. code:: bash

    curl -LO https://github.com/cilium/cilium/archive/master.tar.gz
    tar xzvf cilium-master.tar.gz
    cd cilium-master/install/kubernetes

Install Helm to prepare generating the deployment artifacts based on the Helm templates.

Next, generate the required YAML files and deploy them:

.. code:: bash

    helm template cilium \
        --namespace kube-system \
        --set global.nodePort.enabled=true \
        --set global.kubeConfigPath=/etc/kubernetes/admin.conf \
        --set global.tag=v1.6.0 \
    > cilium.yaml
    kubectl apply -f cilium.yaml

This will install Cilium as a CNI plugin with the BPF kube-proxy replacement.
See :ref:`nodeport` for requirements and configuration options for NodePort
services.

Finally, verify that Cilium has come up correctly on all nodes:

.. parsed-literal::

    kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m
    cilium-mkcmb        1/1       Running   0          10m

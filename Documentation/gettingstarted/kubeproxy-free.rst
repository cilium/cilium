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

.. tabs::

  .. group-tab:: K8s 1.16 and newer

    .. code:: bash

      kubeadm init --pod-network-cidr=10.217.0.0/16 --skip-phases=addon/kube-proxy

  .. group-tab:: K8s 1.15 and older

    In K8s 1.15 and older it is not yet possible to disable kube-proxy via ``--skip-phases=addon/kube-proxy``
    in kubeadm, therefore the below workaround for manually removing the ``kube-proxy`` DaemonSet and
    cleaning the corresponding iptables rules after kubeadm initialization is still necessary (`kubeadm#1733 <https://github.com/kubernetes/kubeadm/issues/1733>`__).

    Initialize control-plane as first step:

    .. code:: bash

      kubeadm init --pod-network-cidr=10.217.0.0/16

    Then delete the ``kube-proxy`` DaemonSet and remove its iptables rules as following:

    .. code:: bash

      kubectl -n kube-system delete ds kube-proxy
      iptables-restore <(iptables-save | grep -v KUBE)

Afterwards, join worker nodes by specifying the control-plane node IP address
and the token returned by ``kubeadm init``:

.. code:: bash

   kubeadm join <..>

.. note:: Newer kernels do not include ``br_netfilter`` module, so you might need to disable netfilter preflight check
          when running your kubeadm ``init`` and ``join`` commands:

          .. code:: bash

             kubeadm <..> --ignore-preflight-errors=FileContent--proc-sys-net-bridge-bridge-nf-call-iptables

          Cilium does not depend on any bridge device whether running with kube-proxy or not,
          so it's safe to skip this step.

.. include:: k8s-install-download-release.rst

Next, generate the required YAML files and deploy them. Replace ``$API_SERVER_IP``
and ``$API_SERVER_PORT`` with the control-plane node IP address and the kube-apiserver
port number reported by ``kubeadm init`` (usually it is ``6443``).

.. code:: bash

    helm template cilium \
        --namespace kube-system \
        --set global.nodePort.enabled=true \
        --set global.k8sServiceHost=$API_SERVER_IP \
        --set global.k8sServicePort=$API_SERVER_PORT \
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

.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _gs_microk8s:

******************************
Getting Started Using MicroK8s
******************************

This guide uses `microk8s <https://microk8s.io/>`_ to demonstrate deployment
and operation of Cilium in a single-node Kubernetes cluster. To run Cilium
inside microk8s, a GNU/Linux distribution with kernel 4.9 or later is
required (per the :ref:`admin_system_reqs`).

Install microk8s
================

#. Install ``microk8s`` >= 1.14 as per microk8s documentation: `MicroK8s User
   guide <https://microk8s.io/docs/>`_.

#. Enable the microk8s DNS service

   ::

      microk8s.enable dns

#. Configure microk8s to use CNI and allow Cilium to register as that CNI:

   .. parsed-literal::

      echo "--allow-privileged" >> /var/snap/microk8s/current/args/kube-apiserver
      sed -i 's/--network-plugin=kubenet/--network-plugin=cni/g'  /var/snap/microk8s/current/args/kubelet
      sed -i 's/--cni-bin-dir=${SNAP}\/opt/--cni-bin-dir=\/opt/g'  /var/snap/microk8s/current/args/kubelet
      sed -i 's/bin_dir = "${SNAP}\/opt/bin_dir = "\/opt/g'  /var/snap/microk8s/current/args/containerd-template.toml
      rm /var/snap/microk8s/current/args/cni-network/cni.conf
      curl \ |SCM_WEB|\/plugins/cilium-cni/05-cilium-cni.conf > /var/snap/microk8s/current/args/cni-network/05-cilium.conf
      systemctl restart snap.microk8s.daemon-containerd.service
      systemctl restart snap.microk8s.daemon-apiserver.service
      systemctl restart snap.microk8s.daemon-kubelet.service

#. Install or configure ``kubectl``.

   * Microk8s provides a version of kubectl, so if you don't otherwise have it
     installed then you can simply alias the microk8s version:

     ::

        snap alias microk8s.kubectl kubectl

   * Alternatively, if you already have kubectl installed then you can simply
     point it at the microk8s version of the kubernetes API server:

     ::

        export KUBECONFIG=/snap/microk8s/current/client.config

Install etcd
============

Install etcd as a ``StatefulSet`` into your new Kubernetes cluster.

.. parsed-literal::

   kubectl create -f \ |SCM_WEB|\/examples/kubernetes/addons/etcd/standalone-etcd.yaml -n kube-system


Install Cilium
==============

Install Cilium as a `DaemonSet <https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/>`_
into your new Kubernetes cluster. The DaemonSet will automatically install
itself as Kubernetes CNI plugin.

.. tabs::

   .. group-tab:: K8s 1.15

      .. parsed-literal::

         kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.15/cilium-microk8s.yaml

   .. group-tab:: K8s 1.14

      .. parsed-literal::

         kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.14/cilium-microk8s.yaml

   .. group-tab:: K8s 1.13

      .. parsed-literal::

         kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-microk8s.yaml

   .. group-tab:: K8s 1.12

      .. parsed-literal::

         kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-microk8s.yaml

   .. group-tab:: K8s 1.11

      .. parsed-literal::

         kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-microk8s.yaml

   .. group-tab:: K8s 1.10

      .. parsed-literal::

         kubectl create -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-microk8s.yaml


Next steps
==========

Now that you have a Kubernetes cluster with Cilium up and running, you can take
a couple of next steps to explore various capabilities:

* :ref:`gs_http`
* :ref:`gs_dns`
* :ref:`gs_cassandra`
* :ref:`gs_kafka`

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
      sed -i 's;--cni-bin-dir=${SNAP}/opt;--cni-bin-dir=/opt;g'  /var/snap/microk8s/current/args/kubelet
      sed -i 's;bin_dir = "${SNAP}/opt;bin_dir = "/opt;g'  /var/snap/microk8s/current/args/containerd-template.toml
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

Install Cilium
==============

.. include:: k8s-install-download-release.rst

Generate the required YAML file and deploy it:

.. code:: bash

   helm template cilium \
     --namespace kube-system \
     --set global.cni.confPath=/var/snap/microk8s/current/args/cni-network \
     --set global.cni.customConf=true \
     --set global.containerRuntime.integration=containerd \
     --set global.containerRuntime.socketPath=/var/snap/microk8s/common/run/containerd.sock \
     > cilium.yaml
   kubectl create -f cilium.yaml

Next steps
==========

Now that you have a Kubernetes cluster with Cilium up and running, you can take
a couple of next steps to explore various capabilities:

* :ref:`gs_http`
* :ref:`gs_dns`
* :ref:`gs_cassandra`
* :ref:`gs_kafka`

.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _chaining_azure:

******************
Azure CNI (Legacy)
******************

.. note::

   For most users, the best way to run Cilium on AKS is either
   AKS BYO CNI as described in :ref:`k8s_install_quick`
   or `Azure CNI Powered by Cilium <https://aka.ms/aks/cilium-dataplane>`__.
   This guide provides alternative instructions to run Cilium with Azure CNI
   in a chaining configuration. This is the legacy way of running Azure CNI with
   cilium as Azure IPAM is legacy, for more information see :ref:`ipam_azure`.

.. include:: cni-chaining-limitations.rst

.. admonition:: Video
 :class: attention

  If you'd like a video explanation of the Azure CNI Powered by Cilium, check out `eCHO episode 70: Azure CNI Powered by Cilium <https://www.youtube.com/watch?v=8it8Hm2F_GM>`__.

This guide explains how to set up Cilium in combination with Azure CNI in a
chaining configuration. In this hybrid mode, the Azure CNI plugin is
responsible for setting up the virtual network devices as well as address
allocation (IPAM). After the initial networking is setup, the Cilium CNI plugin
is called to attach eBPF programs to the network devices set up by Azure CNI to
enforce network policies, perform load-balancing, and encryption.


Create an AKS + Cilium CNI configuration
========================================

Create a ``chaining.yaml`` file based on the following template to specify the
desired CNI chaining configuration. This :term:`ConfigMap` will be installed as the CNI
configuration file on all nodes and defines the chaining configuration. In the
example below, the Azure CNI, portmap, and Cilium are chained together.

.. code-block:: yaml

    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: cni-configuration
      namespace: kube-system
    data:
      cni-config: |-
        {
          "cniVersion": "0.3.0",
          "name": "azure",
          "plugins": [
            {
              "type": "azure-vnet",
              "mode": "transparent",
              "ipam": {
                 "type": "azure-vnet-ipam"
               }
            },
            {
              "type": "portmap",
              "capabilities": {"portMappings": true},
              "snat": true
            },
            {
               "name": "cilium",
               "type": "cilium-cni"
            }
          ]
        }

Deploy the :term:`ConfigMap`:

.. code-block:: shell-session

   kubectl apply -f chaining.yaml


Deploy Cilium
=============

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set cni.chainingMode=generic-veth \\
     --set cni.customConf=true \\
     --set cni.exclusive=false \\
     --set nodeinit.enabled=true \\
     --set cni.configMap=cni-configuration \\
     --set routingMode=native \\
     --set enableIPv4Masquerade=false \\
     --set endpointRoutes.enabled=true

This will create both the main cilium daemonset, as well as the cilium-node-init daemonset, which handles tasks like mounting the eBPF filesystem and updating the
existing Azure CNI plugin to run in 'transparent' mode.

.. include:: k8s-install-restart-pods.rst

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst

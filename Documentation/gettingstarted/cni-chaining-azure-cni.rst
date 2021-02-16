.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

*********
Azure CNI
*********

.. note::

   This is not the best option to run Cilium on AKS or Azure. Please refer to
   :ref:`k8s_install_aks` for the best guide to run Cilium in Azure Cloud.
   Follow this guide if you specifically want to run Cilium in combination with
   the Azure CNI in a chaining configuration.

This guide explains how to set up Cilium in combination with Azure CNI in a
chaining configuration. In this hybrid mode, the Azure CNI plugin is
responsible for setting up the virtual network devices as well as address
allocation (IPAM). After the initial networking is setup, the Cilium CNI plugin
is called to attach eBPF programs to the network devices set up by Azure CNI to
enforce network policies, perform load-balancing, and encryption.


Create an AKS + Cilium CNI configuration
========================================

Create a ``chaining.yaml`` file based on the following template to specify the
desired CNI chaining configuration. This ConfigMap will be installed as the CNI
configuration file on all nodes and defines the chaining configuration. In the
example below, the Azure CNI, portmap, and Cilium are chained together.

.. code:: yaml

    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: cni-configuration
      namespace: cilium
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

Create the cilium namespace:

.. code:: bash

   kubectl create namespace cilium


Deploy the `ConfigMap`:

.. code:: bash

   kubectl apply -f chaining.yaml


Deploy Cilium
=============

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace cilium \\
     --set cni.chainingMode=generic-veth \\
     --set cni.customConf=true \\
     --set nodeinit.enabled=true \\
     --set cni.configMap=cni-configuration \\
     --set tunnel=disabled \\
     --set enableIPv4Masquerade=false

This will create both the main cilium daemonset, as well as the cilium-node-init daemonset, which handles tasks like mounting the eBPF filesystem and updating the
existing Azure CNI plugin to run in 'transparent' mode.

.. include:: k8s-install-restart-pods.rst

Validate the Installation
=========================

You can monitor as Cilium and all required components are being installed:

.. code-block:: shell-session

   $ kubectl -n cilium get pods --watch
   cilium-2twr9                      0/1     Init:0/2            0          17s
   cilium-fkhjv                      0/1     Init:0/2            0          17s
   cilium-node-init-bhr5l            1/1     Running             0          17s
   cilium-node-init-l77v9            1/1     Running             0          17s
   cilium-operator-f8bd5cd96-qdspd   0/1     ContainerCreating   0          17s
   cilium-operator-f8bd5cd96-tvdn6   0/1     ContainerCreating   0          17s

It may take a couple of minutes for all components to come up:

.. code-block:: shell-session

   cilium-operator-f8bd5cd96-tvdn6   1/1     Running             0          25s
   cilium-operator-f8bd5cd96-qdspd   1/1     Running             0          26s
   cilium-fkhjv                      1/1     Running             0          60s
   cilium-2twr9                      1/1     Running             0          61s

.. include:: k8s-install-connectivity-test.rst

.. include:: namespace-cilium.rst
.. include:: hubble-enable.rst


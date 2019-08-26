Create an AKS + Cilium CNI configuration
========================================

Create a ``chaining.yaml`` file based on the following template to specify the
desired CNI chaining configuration:


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
              "bridge": "azure0",
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


Prepare & Deploy Cilium
=======================

.. include:: k8s-install-download-release.rst

Generate the required YAML file and deploy it:

.. code:: bash

   helm template cilium \
     --namespace cilium \
     --set global.cni.chainingMode=generic-veth \
     --set global.cni.customConf=true \
     --set nodeinit.enabled=true \
     --set global.cni.configMap=cni-configuration \
     --set global.tunnel=disabled \
     > cilium.yaml
   kubectl create -f cilium.yaml

This will create both the main cilium daemonset, as well as the cilium-node-init daemonset, which handles tasks like mounting the BPF filesystem and updating the
existing Azure CNI plugin to run in 'transparent' mode.

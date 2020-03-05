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


Deploy Cilium
=============

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace cilium \\
     --set global.cni.chainingMode=generic-veth \\
     --set global.cni.customConf=true \\
     --set global.nodeinit.enabled=true \\
     --set nodeinit.azure=true \\
     --set global.cni.configMap=cni-configuration \\
     --set global.tunnel=disabled \\
     --set global.masquerade=false

This will create both the main cilium daemonset, as well as the cilium-node-init daemonset, which handles tasks like mounting the BPF filesystem and updating the
existing Azure CNI plugin to run in 'transparent' mode.

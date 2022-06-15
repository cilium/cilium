.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

********
Kube-OVN
********

This guide instructs how to install Cilium in chaining configuration on top of
`Kube-OVN <https://github.com/kubeovn/kube-ovn>`_.

.. include:: cni-chaining-limitations.rst

Create a CNI configuration
==========================

Create a ``chaining.yaml`` file based on the following template to specify the
desired CNI chaining configuration:


.. code-block:: yaml

    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: cni-configuration
      namespace: kube-system
    data:
      cni-config: |-
        {
          "name": "generic-veth",
          "cniVersion": "0.3.1",
          "plugins": [
            {
              "type": "kube-ovn",
              "server_socket": "/run/openvswitch/kube-ovn-daemon.sock",
              "ipam": {
                  "type": "kube-ovn",
                  "server_socket": "/run/openvswitch/kube-ovn-daemon.sock"
              }
            },
            {
              "type": "portmap",
              "snat": true,
              "capabilities": {"portMappings": true}
            },
            {
              "type": "cilium-cni"
            }
          ]
        }

Deploy the :term:`ConfigMap`:

.. code-block:: shell-session

   kubectl apply -f chaining.yaml


Change Kube-OVN default install options
=======================================

The Kube-OVN default installation option will implement the networkpolicy by itself,
that can be conflict with Cilium policies. Also the default cni conf priority is higher
than the Cilium one. We need to change the installation options of Kube-OVN to make
Cilium chaining take effect.

.. code-block:: shell-session

   ENABLE_NP=false CNI_CONFIG_PRIORITY=10 bash install.sh


Deploy Cilium with the portmap plugin enabled
=============================================

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
      --namespace=kube-system \\
      --set cni.chainingMode=generic-veth \\
      --set cni.customConf=true \\
      --set cni.configMap=cni-configuration \\
      --set tunnel=disabled \\
      --set enableIPv4Masquerade=false \\
      --set enableIdentityMark=false

.. note::

   The new CNI chaining configuration will *not* apply to any pod that is
   already running in the cluster. Existing pods will be reachable and Cilium will
   load-balance to them but policy enforcement will not apply to them and
   load-balancing is not performed for traffic originating from existing pods.

   You must restart these pods in order to invoke the chaining configuration on
   them.

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst


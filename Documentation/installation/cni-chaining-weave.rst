.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

*********
Weave Net
*********

This guide instructs how to install Cilium in chaining configuration on top of
`Weave Net <https://github.com/weaveworks/weave>`_.

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
            "cniVersion": "0.3.1",
            "name": "weave",
            "plugins": [
                {
                    "name": "weave",
                    "type": "weave-net",
                    "hairpinMode": true
                },
                {
                    "type": "portmap",
                    "capabilities": {"portMappings": true},
                    "snat": true
                },
                {
                    "type": "cilium-cni"
                }
            ]
        }

Deploy the :term:`ConfigMap`:

.. code-block:: shell-session

   kubectl apply -f chaining.yaml

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
      --set routingMode=native \\
      --set enableIPv4Masquerade=false

.. note::

   The new CNI chaining configuration will *not* apply to any pod that is
   already running the cluster. Existing pods will be reachable and Cilium will
   load-balance to them but policy enforcement will not apply to them and
   load-balancing is not performed for traffic originating from existing pods.

   You must restart these pods in order to invoke the chaining configuration on
   them.

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst


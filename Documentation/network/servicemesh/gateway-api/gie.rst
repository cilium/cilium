.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_gie:

*******************************
Gateway API Inference Extension
*******************************

Gateway API Inference Extension (GIE) is an extension of Gateway API that optimizes self-hosting
Generative Models on Kubernetes. GIE's goal it to improve and standardized routing to inference
workloads.

Read more in about `Gateway API Inference Extension in their docs <https://gateway-api-inference-extension.sigs.k8s.io>`_.

.. warning::

    This feature is currently beta and is still under active development. Currently, Cilium
    is partially conforms with the tests (skips ``GatewayWeightedAcrossTwoInferencePools``).


.. include:: installation.rst

Enable Gateway Inference Extension
##################################

The Gateway Inference Extension CRDs ``must`` be installed.

- `InferencePool <https://gateway-api-inference-extension.sigs.k8s.io/api-types/inferencepool/>`_
- `InferencePoolImport <https://gateway-api-inference-extension.sigs.k8s.io/api-types/inferencepoolimport/>`_

You can install the required CRDs like this:

.. parsed-literal::

    kubectl apply -f  https://github.com/kubernetes-sigs/gateway-api-inference-extension/releases/download/v1.6.2/manifests.yaml

Once the CRDs are installed, use Helm or Cilium CLI to enable Cilium Gateway API Inference Extension.

.. tabs::

    .. group-tab:: Helm

        .. include:: ../../../installation/cli-download.rst

        Cilium Gateway API Controller can be enabled with helm flag ``gatewayAPI.enabled``
        set as ``true``. Please refer to :ref:`k8s_install_helm` for a fresh installation.

        .. cilium-helm-upgrade::
           :namespace: kube-system
           :extra-args: --reuse-values
           :set: kubeProxyReplacement=true
                 gatewayAPI.enabled=true
                 gatewayAPI.gatewayAPIInferenceExtension.enabled=true
           :post-commands: kubectl -n kube-system rollout restart deployment/cilium-operator
                           kubectl -n kube-system rollout restart ds/cilium

        Next you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status


    .. group-tab:: Cilium CLI

        .. include:: ../../../installation/cli-download.rst

        Cilium Gateway API Controller can be enabled with the below command.

        .. parsed-literal::

            $ cilium upgrade --version |CHART_VERSION| \\
                --set kubeProxyReplacement=true \\
                --set gatewayAPI.enabled=true \\
                --set gatewayAPI.gatewayAPIInferenceExtension.enabled=true

        Next you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status
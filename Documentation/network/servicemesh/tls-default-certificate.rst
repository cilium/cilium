.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

**********************************
Defaults certificate for Ingresses
**********************************

Cilium can use a default certificate for ingresses without ``.spec.tls[].secretName`` set.
It's still necessary to have ``.spec.tls[].hosts`` defined.

Prerequisites
#############

* Cilium must be configured with Kubernetes Ingress Support.
  Please refer to :ref:`Kubernetes Ingress Support <gs_ingress>` for more details.

Installation
############

.. tabs::

    .. group-tab:: Helm

        Defaults certificate for Ingresses can be enabled with helm flags
        ``ingressController.defaultSecretNamespace`` and
        ``ingressController.defaultSecretName```
        set as true. Please refer to :ref:`k8s_install_helm` for a fresh installation.

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
                --namespace kube-system \\
                --reuse-values \\
                --set ingressController.defaultSecretNamespace=kube-system \\
                --set ingressController.defaultSecretName=default-cert \\

            $ kubectl -n kube-system rollout restart deployment/cilium-operator
            $ kubectl -n kube-system rollout restart ds/cilium

    .. group-tab:: Cilium CLI

        .. include:: ../../installation/cli-download.rst

        Cilium Ingress Controller can be enabled with the following command:

        .. parsed-literal::

            $ cilium install |CHART_VERSION| \
                --set kubeProxyReplacement=true \
                --set ingressController.enabled=true \
                --set ingressController.defaultSecretNamespace=kube-system \
                --set ingressController.defaultSecretName=default-cert

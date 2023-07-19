Prerequisites
#############

* Cilium must be configured with ``kubeProxyReplacement`` as partial
  or strict. Please refer to :ref:`kube-proxy replacement <kubeproxy-free>`
  for more details.
* The minimum supported Kubernetes version for Ingress is 1.19.

Installation
############

.. tabs::

    .. group-tab:: Helm

        Cilium Ingress Controller can be enabled with helm flag ``ingressController.enabled``
        set as true. Please refer to :ref:`k8s_install_helm` for a fresh installation.

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
                --namespace kube-system \\
                --reuse-values \\
                --set ingressController.enabled=true
            $ kubectl -n kube-system rollout restart deployment/cilium-operator
            $ kubectl -n kube-system rollout restart ds/cilium


        If you only want to use envoy traffic management feature without Ingress support, you should only
        enable ``--enable-envoy-config`` flag.

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
                --namespace kube-system \\
                --reuse-values \\
                --set-string extraConfig.enable-envoy-config=true
            $ kubectl -n kube-system rollout restart deployment/cilium-operator
            $ kubectl -n kube-system rollout restart ds/cilium


        Next you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status

        .. include:: ../cli-download.rst

    .. group-tab:: Cilium CLI

        .. include:: ../cli-download.rst

        Cilium Ingress Controller can be enabled with the below command

        .. parsed-literal::

            $ cilium install |CHART_VERSION| \
                --set kubeProxyReplacement=true \
                --set ingressController.enabled=true \

        If you only want to use envoy traffic management feature without Ingress support, you should only
        enable ``--enable-envoy-config`` flag.

        .. parsed-literal::

            $ cilium install |CHART_VERSION| \
                --set kubeProxyReplacement=true \
                --set-string extraConfig.enable-envoy-config=true

        Next you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status

Hubble CLI is also used to observe the traffic in later steps.

.. include:: ../hubble-install.rst

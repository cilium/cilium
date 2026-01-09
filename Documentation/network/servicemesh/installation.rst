Installation
############

.. tabs::

    .. group-tab:: Helm

        Cilium Ingress Controller can be enabled with helm flag ``ingressController.enabled``
        set as true. Please refer to :ref:`k8s_install_helm` for a fresh installation.

        .. cilium-helm-upgrade::
           :namespace: kube-system
           :extra-args: --reuse-values
           :set: ingressController.enabled=true
                 ingressController.loadbalancerMode=dedicated
           :post-commands: kubectl -n kube-system rollout restart deployment/cilium-operator
                           kubectl -n kube-system rollout restart ds/cilium

        Cilium can become the default ingress controller by setting the
        ``--set ingressController.default=true`` flag. This will create ingress entries even when the ``ingressClass`` 
        is not set.

        If you only want to use envoy traffic management feature without Ingress support, you should only
        enable ``--enable-envoy-config`` flag.

        .. cilium-helm-upgrade::
           :namespace: kube-system
           :extra-args: --reuse-values
           :set: envoyConfig.enabled=true
           :post-commands: kubectl -n kube-system rollout restart deployment/cilium-operator
                           kubectl -n kube-system rollout restart ds/cilium

        Additionally, the proxy load-balancing feature can be configured with the ``loadBalancer.l7.backend=envoy`` flag.

        .. cilium-helm-upgrade::
           :namespace: kube-system
           :extra-args: --reuse-values
           :set: loadBalancer.l7.backend=envoy
           :post-commands: kubectl -n kube-system rollout restart deployment/cilium-operator
                           kubectl -n kube-system rollout restart ds/cilium

        Next you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status

        .. include:: ../../installation/cli-download.rst

    .. group-tab:: Cilium CLI

        .. include:: ../../installation/cli-download.rst

        Cilium Ingress Controller can be enabled with the below command

        .. parsed-literal::

            $ cilium install |CHART_VERSION| \
                --set kubeProxyReplacement=true \
                --set ingressController.enabled=true \
                --set ingressController.loadbalancerMode=dedicated

        Cilium can become the default ingress controller by setting the
        ``--set ingressController.default=true`` flag. This will create ingress entries even when the ``ingressClass`` 
        is not set.

        If you only want to use envoy traffic management feature without Ingress support, you should only
        enable ``--enable-envoy-config`` flag.

        .. parsed-literal::

            $ cilium install |CHART_VERSION| \
                --set kubeProxyReplacement=true \
                --set envoyConfig.enabled=true

        Additionally, the proxy load-balancing feature can be configured with the ``loadBalancer.l7.backend=envoy`` flag.

        .. parsed-literal::

            $ cilium install |CHART_VERSION| \
                --set kubeProxyReplacement=true \
                --set envoyConfig.enabled=true \
                --set loadBalancer.l7.backend=envoy

        Next you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status

It is also recommended that you :ref:`install Hubble CLI<hubble_cli_install>`
which will be used used to observe the traffic in later steps.

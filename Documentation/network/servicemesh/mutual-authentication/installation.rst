Prerequisites
#############

* Mutual authentication is only currently supported with SPIFFE APIs for certificate management.
* The Cilium Helm chart includes an option to deploy a SPIRE server for mutual authentication. You may also deploy your own SPIRE server and configure Cilium to use it.

Installation
############

.. tabs::

    .. group-tab:: Helm

        The Cilium Helm chart includes an option to deploy SPIRE server for mutual authentication.
        You may also deploy your own SPIRE server and configure Cilium to use it.
        Please refer to :ref:`k8s_install_helm` for a fresh installation.

        .. parsed-literal::

            $ helm install cilium |CHART_RELEASE| \\
                --namespace kube-system \\
                --reuse-values \\
                --set authentication.mutual.spire.enabled=true \\
                --set authentication.mutual.spire.install.enabled=true

            $ kubectl -n kube-system rollout restart deployment/cilium-operator
            $ kubectl -n kube-system rollout restart ds/cilium

        Next you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status

        .. include:: ../../../installation/cli-download.rst

    .. group-tab:: Cilium CLI

        .. include:: ../../../installation/cli-download.rst

        Mutual authentication and associated SPIRE server can be enabled with the following command.
        Note this requires the Cilium CLI Helm mode (version 0.15 or later).

        .. parsed-literal::

            $ cilium install |CHART_VERSION| \
                --helm-set authentication.mutual.spire.enabled=true \
                --helm-set authentication.mutual.spire.install.enabled=true

        Next you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status


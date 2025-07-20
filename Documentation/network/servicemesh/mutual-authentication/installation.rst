Prerequisites
#############

* Mutual authentication is only currently supported with SPIFFE APIs for certificate management.
* The Cilium Helm chart includes an option to deploy a SPIRE server for mutual authentication. You may also deploy your own SPIRE server and configure Cilium to use it.

Installation
############

.. Note::

    The default installation requires `PersistentVolumeClaim <https://kubernetes.io/docs/concepts/storage/persistent-volumes/>`_
    support in the cluster, so please check with your cluster provider if it's supported or how to enable it.

    For lab or local cluster, you can switch to in-memory storage by passing ``authentication.mutual.spire.install.server.dataStorage.enabled=false``
    to the installation command, at the cost of re-creating all data when the SPIRE server pod is restarted.


.. tabs::

    .. group-tab:: Cilium CLI

        .. include:: ../../../installation/cli-download.rst

        You can enable mutual authentication and its associated SPIRE server with the following command.
        This command requires the Cilium CLI Helm mode version 0.15 or later.

        .. code-block:: shell-session

            $ cilium install \
                --set authentication.mutual.spire.enabled=true \
                --set authentication.mutual.spire.install.enabled=true

        Next, you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status

    .. group-tab:: Helm

        The Cilium Helm chart includes an option to deploy SPIRE server for mutual authentication.
        You may also deploy your own SPIRE server and configure Cilium to use it.
        Please refer to :ref:`k8s_install_helm` for a fresh installation.

        .. parsed-literal::

            $ helm install cilium |CHART_RELEASE| \\
                --namespace kube-system \\
                --set authentication.mutual.spire.enabled=true \\
                --set authentication.mutual.spire.install.enabled=true

            $ kubectl -n kube-system rollout restart deployment/cilium-operator
            $ kubectl -n kube-system rollout restart ds/cilium

        Next, you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status

        .. include:: ../../../installation/cli-download.rst

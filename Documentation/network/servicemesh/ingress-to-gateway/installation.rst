Prerequisites
#############

* Cilium must be configured with ``kubeProxyReplacement`` as partial
  or strict. Please refer to :ref:`kube-proxy replacement <kubeproxy-free>`
  for more details.
* Cilium must be configured with the L7 proxy enabled using the ``--enable-l7-proxy`` flag (enabled by default).
* The below CRDs from Gateway API v0.5.1 ``must`` be pre-installed.
  Please refer to this `docs <https://gateway-api.sigs.k8s.io/guides/?h=crds#getting-started-with-gateway-api>`_
  for installation steps. Alternatively, the below snippet could be used.

    - `GatewayClass <https://gateway-api.sigs.k8s.io/api-types/gatewayclass/>`_
    - `Gateway <https://gateway-api.sigs.k8s.io/api-types/gateway/>`_
    - `HTTPRoute <https://gateway-api.sigs.k8s.io/api-types/httproute/>`_
    - `ReferenceGrant <https://gateway-api.sigs.k8s.io/api-types/referencegrant/>`_

    .. code-block:: shell-session

        $ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v0.5.1/config/crd/standard/gateway.networking.k8s.io_gatewayclasses.yaml
        $ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v0.5.1/config/crd/standard/gateway.networking.k8s.io_gateways.yaml
        $ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v0.5.1/config/crd/standard/gateway.networking.k8s.io_httproutes.yaml
        $ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v0.5.1/config/crd/experimental/gateway.networking.k8s.io_referencegrants.yaml

* Similar to Ingress, Gateway API controller creates a service of LoadBalancer type,
  so your environment will need to support this.

Installation
############

.. tabs::

    .. group-tab:: Helm

        Cilium Gateway API Controller can be enabled with helm flag ``gatewayAPI.enabled``
        set as true. Please refer to :ref:`k8s_install_helm` for a fresh installation.

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
                --namespace kube-system \\
                --reuse-values \\
                --set gatewayAPI.enabled=true

            $ kubectl -n kube-system rollout restart deployment/cilium-operator
            $ kubectl -n kube-system rollout restart ds/cilium

        Next you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status

        .. include:: ../../../installation/cli-download.rst

    .. group-tab:: Cilium CLI

        .. include:: ../../../installation/cli-download.rst

        Cilium Gateway API Controller can be enabled with the below command

        .. code-block:: shell-session

            $ cilium install \\
                --kube-proxy-replacement=strict \\
                --helm-set gatewayAPI.enabled=true

        Next you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status


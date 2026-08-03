Prerequisites
#############

* Cilium must be configured with the kube-proxy replacement, using
  ``kubeProxyReplacement=true``. For more information, see :ref:`kube-proxy
  replacement <kubeproxy-free>`.
* Cilium must be configured with the L7 proxy enabled using ``l7Proxy=true``
  (enabled by default).
* By default, the Cilium Gateway API controller creates a service of LoadBalancer type,
  so your environment will need to support this. Alternatively, since Cilium 1.16,
  you can directly expose the Cilium L7 proxy on the :ref:`host network <gs_gateway_host_network_mode>`.

Installation
############

The below CRDs from Gateway API |GATEWAY_API_VERSION| ``must`` be installed.

- `GatewayClass <https://gateway-api.sigs.k8s.io/reference/api-types/gatewayclass/>`_
- `Gateway <https://gateway-api.sigs.k8s.io/reference/api-types/gateway/>`_
- `HTTPRoute <https://gateway-api.sigs.k8s.io/reference/api-types/httproute/>`_
- `GRPCRoute <https://gateway-api.sigs.k8s.io/reference/api-types/grpcroute/>`_
- `BackendTLSPolicy <https://gateway-api.sigs.k8s.io/reference/api-types/policy/backendtlspolicy/>`__
- `ReferenceGrant <https://gateway-api.sigs.k8s.io/reference/api-types/referencegrant/>`_
- `TLSRoute <https://gateway-api.sigs.k8s.io/reference/api-types/tlsroute/>`_

Please refer to these `docs <https://gateway-api.sigs.k8s.io/guides/getting-started/introduction/#installing-gateway-api>`__
for installation steps. Alternatively, the below snippet could be used.

Note that the **experimental** release channel includes everything in the **standard**
release channel plus some experimental resources and fields. If you need
a feature that is currently marked as *experimental* (for example, HTTPRoute Retry in the ``HTTPRoute`` resource),
you must install the corresponding CRDs. Please refer to `the experimental GEP list <https://gateway-api.sigs.k8s.io/geps/by-state/experimental/>`__
for a full list of experimental features.

If you are updating your current installation, make sure to always check the :ref:`admin_upgrade`
first to review any breaking changes, deprecated features, or important configuration updates needed for the new version.
For Cilium 1.20 upgrades, review the Gateway API v1.6.1 and ``TLSRoute`` notes in the upgrade guide before updating Gateway API CRDs.

You can install the set of required CRDs like this:

.. tabs::

  .. group-tab:: Standard

    .. parsed-literal::

      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_gatewayclasses.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_gateways.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_httproutes.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_referencegrants.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_grpcroutes.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_backendtlspolicies.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_tlsroutes.yaml

  .. group-tab:: Experimental

    .. parsed-literal::

      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/experimental/gateway.networking.k8s.io_gatewayclasses.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/experimental/gateway.networking.k8s.io_gateways.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/experimental/gateway.networking.k8s.io_httproutes.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/experimental/gateway.networking.k8s.io_referencegrants.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/experimental/gateway.networking.k8s.io_grpcroutes.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/experimental/gateway.networking.k8s.io_backendtlspolicies.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml

The `TCPRoute <https://gateway-api.sigs.k8s.io/reference/api-types/tcproute/>`__,
`UDPRoute <https://gateway-api.sigs.k8s.io/reference/api-types/udproute/>`__,
or `ListenerSet <https://gateway-api.sigs.k8s.io/reference/api-types/listenerset/>`__
CRDs are optional and to use this functionality, you must install the corresponding CRD resources.
If they are not installed, Cilium will disable support for these features.

You can install the set of optional CRDs like this:

.. tabs::

  .. group-tab:: Standard

    .. parsed-literal::

      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_listenersets.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_tcproutes.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_udproutes.yaml

  .. group-tab:: Experimental

    .. parsed-literal::

      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/experimental/gateway.networking.k8s.io_listenersets.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/experimental/gateway.networking.k8s.io_tcproutes.yaml
      kubectl apply --server-side -f |GATEWAY_API_RAW_BASE_URL|/config/crd/experimental/gateway.networking.k8s.io_udproutes.yaml

Once CRDs are installed, use Helm or Cilium CLI to enable Cilium Gateway API controller.

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
                --set gatewayAPI.enabled=true

        Next you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status

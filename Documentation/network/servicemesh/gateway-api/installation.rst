Prerequisites
#############

* Cilium must be configured with the kube-proxy replacement, using
  ``kubeProxyReplacement=true``. For more information, see :ref:`kube-proxy
  replacement <kubeproxy-free>`.
* Cilium must be configured with the L7 proxy enabled using ``l7Proxy=true``
  (enabled by default).
* The below CRDs from Gateway API |GATEWAY_API_VERSION| ``must`` be pre-installed.
  Please refer to these `docs <https://gateway-api.sigs.k8s.io/guides/getting-started/introduction/#installing-gateway-api>`_
  for installation steps. Alternatively, the below snippet could be used.

    - `GatewayClass <https://gateway-api.sigs.k8s.io/reference/api-types/gatewayclass/>`_
    - `Gateway <https://gateway-api.sigs.k8s.io/reference/api-types/gateway/>`_
    - `HTTPRoute <https://gateway-api.sigs.k8s.io/reference/api-types/httproute/>`_
    - `GRPCRoute <https://gateway-api.sigs.k8s.io/reference/api-types/grpcroute/>`_
    - `BackendTLSPolicy <https://gateway-api.sigs.k8s.io/reference/api-types/policy/backendtlspolicy/>`__
    - `ReferenceGrant <https://gateway-api.sigs.k8s.io/reference/api-types/referencegrant/>`_
    - `TLSRoute <https://gateway-api.sigs.k8s.io/reference/api-types/tlsroute/>`_

  You can install the set of required CRDs like this:

    .. parsed-literal::

        kubectl apply -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_gatewayclasses.yaml
        kubectl apply -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_gateways.yaml
        kubectl apply -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_httproutes.yaml
        kubectl apply -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_referencegrants.yaml
        kubectl apply -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_grpcroutes.yaml
        kubectl apply -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_backendtlspolicies.yaml
        kubectl apply -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_tlsroutes.yaml


    .. warning::

      If you have used the ``TLSRoute`` resource in releases before Cilium v1.20, you should install the Experimental version of the TLSRoute resource instead.

      If you install the Standard version, *all your TLSRoutes will not be readable*.

      The Standard version of the ``TLSRoute`` resource in Gateway API v1.6 does *not* include the ``v1alpha2`` version that TLSRoute previously used, which
      means that the apiserver cannot read the records in etcd.

      Install the experimental version with:

      .. parsed-literal::

        kubectl apply -f |GATEWAY_API_RAW_BASE_URL|/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml

  If you wish to use the ListenerSet, TCPRoute, or UDPRoute functionality, you
  also need to install the related CRDs. For each CRD that is not installed,
  Cilium will disable support for the feature.

    - `ListenerSet <https://gateway-api.sigs.k8s.io/reference/api-types/listenerset/>`__
    - `TCPRoute <https://gateway-api.sigs.k8s.io/reference/api-types/tcproute/>`__
    - `UDPRoute <https://gateway-api.sigs.k8s.io/reference/api-types/udproute/>`__

  Each optional CRD can be installed with these respective commands.

  ListenerSet:

    .. parsed-literal::

        kubectl apply -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_listenersets.yaml

  TCPRoute:

    .. parsed-literal::

        kubectl apply -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_tcproutes.yaml

  UDPRoute:

    .. parsed-literal::

        kubectl apply -f |GATEWAY_API_RAW_BASE_URL|/config/crd/standard/gateway.networking.k8s.io_udproutes.yaml

* By default, the Gateway API controller creates a service of LoadBalancer type,
  so your environment will need to support this. Alternatively, since Cilium 1.16+,
  you can directly expose the Cilium L7 proxy on the :ref:`host network <gs_gateway_host_network_mode>`.

Installation
############

.. include:: ../../../installation/cli-download.rst

.. tabs::

    .. group-tab:: Helm

        Cilium Gateway API Controller can be enabled with helm flag ``gatewayAPI.enabled``
        set as true. Please refer to :ref:`k8s_install_helm` for a fresh installation.

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

        Cilium Gateway API Controller can be enabled with the below command

        .. parsed-literal::

            $ cilium install |CHART_VERSION| \\
                --set kubeProxyReplacement=true \\
                --set gatewayAPI.enabled=true

        Next you can check the status of the Cilium agent and operator:

        .. code-block:: shell-session

            $ cilium status

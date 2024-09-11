Prerequisites
#############

* Cilium must be configured with NodePort enabled, using
  ``nodePort.enabled=true`` or by enabling the kube-proxy replacement with
  ``kubeProxyReplacement=true``. For more information, see :ref:`kube-proxy
  replacement <kubeproxy-free>`.
* Cilium must be configured with the L7 proxy enabled using ``l7Proxy=true``
  (enabled by default).
* The below CRDs from Gateway API v1.1.0 ``must`` be pre-installed.
  Please refer to this `docs <https://gateway-api.sigs.k8s.io/guides/?h=crds#getting-started-with-gateway-api>`_
  for installation steps. Alternatively, the below snippet could be used.

    - `GatewayClass <https://gateway-api.sigs.k8s.io/api-types/gatewayclass/>`_
    - `Gateway <https://gateway-api.sigs.k8s.io/api-types/gateway/>`_
    - `HTTPRoute <https://gateway-api.sigs.k8s.io/api-types/httproute/>`_
    - `GRPCRoute <https://gateway-api.sigs.k8s.io/api-types/grpcroute/>`_
    - `ReferenceGrant <https://gateway-api.sigs.k8s.io/api-types/referencegrant/>`_

  If you wish to use the TLSRoute functionality, you'll also need to install the TLSRoute resource.
  If this CRD is not installed, then Cilium will disable TLSRoute support.

    - `TLSRoute (experimental) <https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io%2fv1alpha2.TLSRoute/>`_

  You can install the required CRDs like this:

    .. code-block:: shell-session

        $ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.1.0/config/crd/standard/gateway.networking.k8s.io_gatewayclasses.yaml
        $ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.1.0/config/crd/standard/gateway.networking.k8s.io_gateways.yaml
        $ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.1.0/config/crd/standard/gateway.networking.k8s.io_httproutes.yaml
        $ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.1.0/config/crd/standard/gateway.networking.k8s.io_referencegrants.yaml
        $ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.1.0/config/crd/standard/gateway.networking.k8s.io_grpcroutes.yaml

  And add TLSRoute with this snippet.
    .. code-block:: shell-session

        $ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.1.0/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml

* By default, the Gateway API controller creates a service of LoadBalancer type,
  so your environment will need to support this. Alternatively, since Cilium 1.16+,
  you can directly expose the Cilium L7 proxy on the :ref:`host network <gs_gateway_host_network_mode>`.

.. include:: ../ingress-known-issues.rst

Installation
############

.. include:: ../../../installation/cli-download.rst

.. tabs::

    .. group-tab:: Helm

        Cilium Gateway API Controller can be enabled with helm flag ``gatewayAPI.enabled``
        set as true. Please refer to :ref:`k8s_install_helm` for a fresh installation.

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
                --namespace kube-system \\
                --reuse-values \\
                --set kubeProxyReplacement=true \\
                --set gatewayAPI.enabled=true

            $ kubectl -n kube-system rollout restart deployment/cilium-operator
            $ kubectl -n kube-system rollout restart ds/cilium

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


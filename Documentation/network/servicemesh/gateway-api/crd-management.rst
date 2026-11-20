.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Gateway API CRD management
**************************

Instead of installing the Gateway API CRDs yourself, you can let the Cilium
Operator install and upgrade them. The CRDs then always match the Gateway API
version Cilium is built with.

Enable it with the ``gatewayAPI.installCRDs`` Helm value (disabled by default):

.. code-block:: yaml

    kubeProxyReplacement: true
    gatewayAPI:
      enabled: true
      installCRDs: true

When it starts, the Cilium Operator installs the **standard** channel CRDs of
Gateway API |GATEWAY_API_VERSION| (``GatewayClass``, ``Gateway``,
``HTTPRoute``, ``GRPCRoute``, ``TLSRoute``, ``TCPRoute``, ``UDPRoute``,
``ListenerSet``, ``ReferenceGrant`` and ``BackendTLSPolicy``).

When ``gatewayAPI.gatewayClass.create`` is ``auto`` (the default), the Cilium
Operator also creates the default ``cilium`` GatewayClass if it doesn't exist,
and the next ``helm upgrade`` adopts it. When it is ``false``, no GatewayClass
is created.

List the CRDs managed by the Cilium Operator with:

.. code-block:: shell-session

    $ kubectl get crd -l app.kubernetes.io/managed-by=cilium-operator \
        -o custom-columns='NAME:.metadata.name,VERSION:.metadata.annotations.gateway\.networking\.k8s\.io/bundle-version,CHANNEL:.metadata.annotations.gateway\.networking\.k8s\.io/channel'

.. note::

    The **experimental** channel is not supported. If you need experimental
    resources or fields, install the CRDs yourself as described in
    :ref:`gs_gateway_api_prerequisites`.

.. warning::

    Do not set ``gatewayAPI.gatewayClass.create=true`` together with
    ``gatewayAPI.installCRDs`` on a cluster without the Gateway API CRDs: the
    Helm installation fails, as the ``GatewayClass`` CRD doesn't exist yet. Keep
    the default ``auto`` value.

Upgrades
========

The Cilium Operator only manages the CRDs labeled with
``app.kubernetes.io/managed-by: cilium-operator``. When Cilium is upgraded, it
upgrades these CRDs to the new bundled version.

The Cilium Operator never:

* downgrades a CRD, e.g. after a Cilium downgrade;
* modifies a CRD switched to the experimental channel;
* modifies a CRD without the label above;
* deletes a CRD.

CRDs managed by other tools
===========================

The Cilium Operator never takes over CRDs already installed with another tool,
such as ``kubectl``, Helm, Flux or Argo CD. If their version is older than
|GATEWAY_API_VERSION|, the Cilium Operator logs an error, and Gateway API
features may not work as expected.

To fix this, either upgrade the CRDs with the tool managing them and keep
``gatewayAPI.installCRDs`` disabled, or hand the CRDs over to the Cilium
Operator:

#. Make sure the tool which installed the CRDs won't delete them when they are
   removed from its configuration, as deleting a CRD deletes all its resources:

   * Flux: add the ``kustomize.toolkit.fluxcd.io/prune: disabled`` annotation.
   * Argo CD: add the ``argocd.argoproj.io/sync-options: Prune=false``
     annotation.
   * Helm: add the ``helm.sh/resource-policy: keep`` annotation.

#. Remove the CRDs from the configuration of that tool.

#. Label the CRDs:

   .. code-block:: shell-session

       $ kubectl label crd <name> app.kubernetes.io/managed-by=cilium-operator --overwrite

#. Restart the Cilium Operator:

   .. code-block:: shell-session

       $ kubectl -n kube-system rollout restart deployment/cilium-operator

To manage the CRDs yourself again, for instance to switch to the experimental
channel:

#. Disable ``gatewayAPI.installCRDs``.
#. Remove the ``app.kubernetes.io/managed-by`` label from the CRDs.

.. note::

    The Gateway API ``safe-upgrades`` ``ValidatingAdmissionPolicy``, which
    prevents switching standard CRDs to the experimental channel and
    downgrading CRDs, is not installed by the Cilium Operator.

Disabling and uninstalling
==========================

Disabling ``gatewayAPI.installCRDs`` or ``gatewayAPI.enabled``, or uninstalling
Cilium, never deletes the Gateway API CRDs. The CRDs are left as they are, and
are no longer upgraded.

.. warning::

    Deleting a CRD deletes all its resources (e.g. all ``Gateway`` and
    ``HTTPRoute`` resources), and the CRDs may be used by other Gateway API
    implementations. Only delete them with ``kubectl delete crd <name>`` once
    you are sure they are no longer used.

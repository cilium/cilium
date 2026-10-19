.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Gateway API CRD management
**************************

Instead of installing the Gateway API CRDs separately, the Cilium Operator can
install and upgrade them. This avoids an independent lifecycle for the CRDs,
and makes sure that their version matches the one required by Cilium. This is
disabled by default, and is enabled with the ``gatewayAPI.installCRDs`` Helm
value:

.. code-block:: yaml

    kubeProxyReplacement: true
    gatewayAPI:
      enabled: true
      installCRDs: true

When enabled, the Cilium Operator installs the **standard** channel CRDs of
Gateway API |GATEWAY_API_VERSION| when it starts: ``GatewayClass``,
``Gateway``, ``HTTPRoute``, ``GRPCRoute``, ``TLSRoute``, ``TCPRoute``,
``UDPRoute``, ``ListenerSet``, ``ReferenceGrant`` and ``BackendTLSPolicy``.
The CRDs are embedded in the Cilium Operator image, and are always the ones of
the Gateway API version Cilium is built and tested with: there is no option to
select another version, and nothing is downloaded at runtime. The
**experimental** channel is not supported: if you need experimental resources
or fields, keep installing the CRDs yourself as described above.

The CRDs installed by the Cilium Operator are labeled with
``app.kubernetes.io/managed-by: cilium-operator``. Every time it starts (e.g.
when Cilium is upgraded), the Cilium Operator:

* creates the CRDs which are missing;
* upgrades the CRDs carrying the label above whose
  ``gateway.networking.k8s.io/bundle-version`` annotation is older than the
  bundled version;
* never downgrades a CRD with a newer version, e.g. after a Cilium downgrade;
* never modifies a CRD without the label above, nor a CRD whose
  ``gateway.networking.k8s.io/channel`` annotation was changed to
  ``experimental``, as switching channel or downgrading can remove fields or
  API versions, and hence configuration from existing resources;
* never deletes any CRD.

CRDs which are already up-to-date are not written. The CRDs are installed
before the Gateway API controller starts, and the installation waits for them
to be established. If the Kubernetes API server cannot be reached, the
Cilium Operator shuts down and is restarted, as for the Cilium CRDs. The
installation can be followed in the Cilium Operator logs, and conflicts are
also reported by its health status (``cilium-operator status`` /
``cilium status``).

As Helm cannot create the default ``cilium`` GatewayClass before its CRD is
installed, the Cilium Operator creates it if it doesn't exist, when
``gatewayAPI.gatewayClass.create`` is ``auto`` (the default). The GatewayClass
is labeled and annotated as owned by the Cilium Helm release, so that the next
``helm upgrade`` adopts it, as if it had been created by Helm. An existing
GatewayClass is never modified by the Cilium Operator. Do not set
``gatewayAPI.gatewayClass.create=true`` together with ``gatewayAPI.installCRDs``
on a cluster without the Gateway API CRDs, as the Helm installation would fail.

You can list the CRDs managed by the Cilium Operator with:

.. code-block:: shell-session

    $ kubectl get crd -l app.kubernetes.io/managed-by=cilium-operator \
        -o custom-columns='NAME:.metadata.name,VERSION:.metadata.annotations.gateway\.networking\.k8s\.io/bundle-version,CHANNEL:.metadata.annotations.gateway\.networking\.k8s\.io/channel'

CRDs managed by other tools
===========================

Enabling ``gatewayAPI.installCRDs`` never takes ownership of CRDs which are
already installed, for instance with ``kubectl``, Helm, Flux or Argo CD.
They are checked, but left untouched:

* If their version is at least the bundled one (on either channel), they are
  used as-is.
* If their version is older, or unknown, the Cilium Operator logs an error
  and reports a degraded health status, but keeps running. Gateway API
  features may not work as expected until the conflict is resolved.

To resolve such a conflict, either:

* upgrade the CRDs to at least Gateway API |GATEWAY_API_VERSION| with the tool
  managing them, and keep ``gatewayAPI.installCRDs`` disabled; or
* hand the CRDs over to the Cilium Operator. First make sure the tool which
  installed them won't delete them when they are removed from its
  configuration (deleting a CRD deletes all its resources). For instance,
  disable pruning with the ``kustomize.toolkit.fluxcd.io/prune: disabled``
  annotation for Flux, the ``argocd.argoproj.io/sync-options: Prune=false``
  annotation for Argo CD, or the ``helm.sh/resource-policy: keep`` annotation
  for Helm, and then remove them from that tool. Then label the CRDs and
  restart the Cilium Operator:

  .. code-block:: shell-session

      $ kubectl label crd <name> app.kubernetes.io/managed-by=cilium-operator --overwrite
      $ kubectl -n kube-system rollout restart deployment/cilium-operator

Conversely, to manage the CRDs yourself again (for instance to switch to the
experimental channel), remove the label and disable ``gatewayAPI.installCRDs``.
Note that applying the experimental CRDs on top of the CRDs managed by the
Cilium Operator with ``kubectl apply --server-side`` keeps the label: the
Cilium Operator detects the channel change and stops managing them, but you
should still remove the label.

The Gateway API ``safe-upgrades`` ``ValidatingAdmissionPolicy``, which prevents
installing experimental CRDs on top of standard ones and older versions, is not
installed by the Cilium Operator.

Disabling and uninstalling
==========================

Disabling ``gatewayAPI.installCRDs`` or ``gatewayAPI.enabled``, or uninstalling
Cilium, never deletes the Gateway API CRDs: deleting a CRD deletes all its
resources (e.g. all ``Gateway`` and ``HTTPRoute`` resources), and the CRDs may
be used by other Gateway API implementations. When the option is disabled, the
CRDs are no longer upgraded by the Cilium Operator, and are left as they are.
To delete them, make sure they are no longer used, list them with the
``kubectl get crd`` command above, and delete them individually with
``kubectl delete crd <name>``.

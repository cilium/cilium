.. _current_release_required_changes:

|CURRENT_RELEASE| Upgrade Notes
-------------------------------

Action Required
~~~~~~~~~~~~~~~

If you are using the following features in your environment, then you may need
to take action because of changes to the behavior of these features. Read the
notes carefully below to understand what to do during upgrade.

* TODO

Informational Notes
~~~~~~~~~~~~~~~~~~~

* CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy resources that specify
  neither ``spec`` nor ``specs`` are now rejected at admission time by the
  Kubernetes API server via a CEL validation rule. Previously, such empty
  policies were accepted and only flagged later by the Cilium agent with a
  warning log. Existing empty policies already present in the cluster are not
  affected, but any create or update that results in an empty policy will be
  rejected.
* The Azure IPAM status on ``CiliumNode`` now tracks the subnet at the
  interface level, matching the AWS and AlibabaCloud IPAM representations.
  All IP configurations on an Azure NIC must share a subnet, so the new
  ``status.azure.interfaces[].subnet`` object (``id`` and ``cidr``) is the
  authoritative source of subnet information. The previously redundant
  ``status.azure.interfaces[].addresses[].subnet`` and flat
  ``status.azure.interfaces[].cidr`` fields are deprecated and continue to
  be populated as mirrors for one release so that operator and agent
  rolling upgrades work in either order and so that external consumers
  parsing the CRD have a window to switch their reads to
  ``status.azure.interfaces[].subnet``. A future release will remove both
  deprecated fields.
* Cilium MCS-API implementation now uses the ``v1beta1`` version of the
  MCS-API CRDs. Note that ``v1alpha1`` remains fully supported, and this
  upgrade should be fully transparent. You are still encouraged to update
  your ``ServiceExport`` resources to ``v1beta1`` to benefit from future
  improvements and prepare for the eventual deprecation of ``v1alpha1``.
* Listing BGP peers, routes and route-policies via the local REST API and ``cilium-dbg bgp`` commands is deprecated.
  Use the BGP hive shell commands instead: ``cilium shell -- bgp/*``.
* The default duration of automatically generated Cluster Mesh certificates is
  reduced to one year, and matches the default duration of Hubble certificates.
  Note that certificates generated through the ``helm`` method (default) are
  only renewed when the Helm chart is re-rendered (typically during a Cilium
  upgrade). Make sure to upgrade Cilium at least once per year to prevent the
  certificates from expiring, or explicitly configure a longer validity through
  the ``clustermesh.apiserver.tls.auto.certValidityDuration`` option. The same
  limitation does not apply to the other generation methods (``cronJob`` and
  ``certmanager``), which support automatic certificate renewal.
* The certgen tool, which is used to automatically generate Hubble and Cluster
  Mesh certificates in ``cronJob`` mode, now defaults to enforcing that the CA
  chain remains valid for the entire duration of the leaf certificates to be
  generated, and fails with a hard error if that is not the case. This allows
  to flag early situations in which the CA certificates need to be manually
  regenerated, before they actually expire. This validation can be disabled
  setting ``certgen.enforceCAValidityThroughoutLeavesDuration=false``.

Changes to Features
~~~~~~~~~~~~~~~~~~~

* When using the ``KubeProxyReplacement`` for Service Loadbalancing with ``SocketLB`` either
  disabled or configured with ``socketLB.hostNamespaceOnly=true``, in-cluster connections to
  NodePort services by regular pods are now immediately load-balanced when network traffic leaves
  the client pod (and not at the targeted node). This matches the behavior when SocketLB is enabled.
  The client pod's NetworkPolicy consequently needs to allow egress traffic towards the service's
  backends, and the backends' NetworkPolicy needs to allow ingress traffic by the client pod.

New Options
###########

The following options have been introduced in this version of Cilium:

* The ``configDriftDetection`` Helm value group has been introduced to control
  ConfigMap drift detection, which is enabled by default. Cilium exposes a
  Prometheus metric that reports how many configuration keys the agent has not
  yet applied, making it easy to detect when an agent restart is needed after
  a ConfigMap change. See :ref:`configmap-drift-detection` for details.

* ``bpf.datapathMode=auto`` config option has been introduced. If set, Cilium will probe
  the underlying host for netkit support and, if found, netkit mode will be selected at
  runtime. Otherwise, Cilium will default back to the standard veth mode. This has the
  side effect of splitting the datapath-mode into "configured mode" and "operational mode"
  in status outputs, where they differ. The default remains ``bpf.datapathMode=veth``
  but may change in future releases.

Changed Options
###############

The following options have been modified in this version of Cilium to behave
differently than in prior releases:

* ``bpf.tproxy=true`` is incompatible with netkit datapath mode. If netkit is also enabled,
  Cilium will fail to start. If auto-detect datapath mode is used, Cilium will revert to
  veth mode, even if netkit support is present.
* The ``clustermesh.apiserver.tls.server.{extraDnsNames,extraIpAddresses}`` options are
  replaced by ``clustermesh.apiserver.tls.auto.server.{extraDnsNames,extraIpAddresses}``.
  The previous values, if set, are still used as a fallback for backwards compatibility.
  The ``clustermesh-apiserver.cilium.io`` DNS name is also no longer included by default.
* Cluster Mesh certificates are now configured to be automatically regenerated every
  4 months, when the ``cronJob`` generation mode is selected.

Deprecated Options
##################

The following options have been deprecated in this version of Cilium. A future
version of Cilium will remove these options, so if you use these options then
you may need to take action to migrate to an alternative.

* The ``hubble.preferIpv6`` Helm value and ``--hubble-prefer-ipv6`` agent flag
  have been deprecated and will be removed in Cilium 1.20. Use the top-level
  ``preferIpv6`` Helm value and ``--prefer-ipv6`` agent flag instead, which
  apply to both health probes and Hubble peer communication.

* The ``--tofqdns-pre-cache`` agent flag and the corresponding Helm value
  ``dnsProxy.preCache`` have been deprecated and will be removed in v1.21.

Removed Options
###############

The following options were previously deprecated, and they are now removed
from Cilium.

* The previously deprecated Helm value ``clustermesh.enableMCSAPISupport`` was
  removed in favor of the ``clustermesh.mcsapi.enabled`` Helm value.
* The ``encryption.ipsec.interface`` Helm flag (the ``--encrypt-interface``
  agent flag) was a no-op since Cilium 1.18 and has now been removed.

* Support for Envoy Go Extensions (proxylib) and Kafka-aware network policies
  has been removed. These features were deprecated in v1.18.

* The ``v2alpha1`` API version of ``CiliumNodeConfig`` has been removed.
  ``CiliumNodeConfig`` resources must now use ``apiVersion: cilium.io/v2``,
  which has been available since Cilium 1.16. Update any existing
  ``CiliumNodeConfig`` manifests or tooling that references
  ``cilium.io/v2alpha1`` to use ``cilium.io/v2`` instead.

* The Helm value ``hubble.redact.kafka.apiKey`` and the corresponding
  ``hubble-redact-kafka-apikey`` agent flag have been removed as part of
  dropping Kafka support.

* The previously deprecated and ignored ``--ces-slice-mode`` operator flag has been removed.

* The previously deprecated ``--node-port-algorithm`` agent flag has been removed
  in favor of ``--bpf-lb-algorithm`` (``loadBalancer.algorithm`` Helm value).

* The previously deprecated ``--node-port-mode`` agent flag has been removed
  in favor of the ``--bpf-lb-mode`` (``loadBalancer.mode`` Helm value).

* The previously deprecated and ignored ``--enable-ipsec-encrypted-overlay`` agent
  flag (Helm ``encryption.ipsec.encryptedOverlay``) has been removed.

* The previously deprecated ``--enable-encryption-strict-mode`` agent flag
  (Helm ``encryption.strictMode.enabled``) has been removed in favor of
  ``--enable-encryption-strict-mode-egress`` (Helm ``encryption.strictMode.egress.enabled``).

* The previously deprecated ``--encryption-strict-mode-cidr`` agent flag
  (Helm ``encryption.strictMode.cidrs``) has been removed in favor of
  ``--encryption-strict-egress-cidr"`` (Helm ``encryption.strictMode.egress.cidrs``).

* The previously deprecated ``--encryption-strict-mode-allow-remote-node-identities``
  agent flag (Helm ``encryption.strictMode.allowRemoteNodeIdentities``) has been
  removed in favor of ``--encryption-strict-egress-allow-remote-node-identities``
  (Helm ``encryption.strictMode.egress.allowRemoteNodeIdentities``).

* The previously deprecated ``--k8s-api-server`` agent flag has been removed in
  favor of ``--k8s-api-server-urls`` (Helm ``k8s.apiServerURLs`` value).

* The ``cilium-dbg preflight fqdn-poller`` subcommand and the
  ``preflight.tofqdnsPreCache`` Helm value have been removed. These were
  originally introduced for the v1.3 to v1.4 upgrade path and are no longer
  needed.

* The previously deprecated ``cilium-docker-plugin`` has been removed.

* The previously deprecated support for providing Cluster Mesh TLS certificates
  and keys as helm values has been removed. You are now expected to pre-create
  these secrets outside of the Cilium Helm chart when setting
  ``clustermesh.apiserver.tls.auto.enabled=false``.

Changes to Metrics
~~~~~~~~~~~~~~~~~~

Added Metrics
#############

* ``cilium_policy_missing_proxy_redirects`` was added and reports the total number of
  proxy redirects that were missing during endpoint policy calculation.
* ``cilium_endpoint_component_status`` was added and reports the number of endpoints
  tagged by the status (``OK``, ``Warning``, ``Failure``) of each component (``BPF``, ``Policy``).
* ``cilium_kubernetes_resource_sync_duration`` was added and reports duration in seconds
  of a specific Kubernetes resource sync.
* ``cilium_hive_start_duration`` was added and reports the hive.Start method duration.
* ``cilium_hive_stop_duration`` was added and reports the hive.Stop method duration.
  Not reported when metrics are handled by a hive (common in cilium-agent and cilium-operator). Disabled by default.
* ``cilium_hive_populate_duration`` was added and reports the hive.Populate method duration.

Changed Metrics
###############

* The Cilium Operator REST API endpoint ``/v1/metrics`` (``DumpMetrics``) now
  returns per-quantile values for histogram and summary metrics instead of a
  raw sample sum. Histogram metrics now emit three entries with quantile labels
  ``0.5``, ``0.9``, and ``0.99``. Summary metrics emit one entry per declared
  quantile. This aligns the operator metrics API output with the behavior of
  ``cilium-dbg metrics list``.
* The ``cilium_feature_np_other_l7_policies_total`` metric no longer counts
  Kafka policies, as Kafka-aware network policy support has been removed.
* The metric ``policy_change_total`` now reports additional ``source`` (directory, k8s, custom, generated)
  and ``operation`` (update, delete) dimensions.
* The metric ``endpoint_regeneration_total`` now reports additional ``reason`` and ``error`` dimensions.
* The ``session_state``, ``advertised_routes``, ``received_routes``, ``reconcile_errors_total``, ``reconcile_run_duration_seconds`` metrics
  now include ``instance_name`` label. Label ``vrouter`` is removed please use ``instance_name`` instead.
* The ``session_state``, ``advertised_routes``, ``received_routes`` metrics now include ``local_asn`` label.

Deprecated Metrics
##################

* TODO

Removed Metrics
###############

* ``cilium_agent_bootstrap_seconds`` has been removed. Please use ``cilium_hive_jobs_oneshot_last_run_duration_seconds`` of respective job instead.
* ``cilium_operator_ipam_ips`` has been removed. Use per-node ``cilium_operator_ipam_available_ips``, ``cilium_operator_ipam_used_ips``, and ``cilium_operator_ipam_needed_ips`` instead.
* ``cilium_operator_ipam_available_interfaces`` has been removed. Use ``cilium_operator_ipam_interface_candidates`` and ``cilium_operator_ipam_empty_interface_slots`` instead.

Removed CRD Fields
~~~~~~~~~~~~~~~~~~~

The following obsolete fields have been removed from the ``CiliumNode`` CRD:

* ``spec.eni.instance-id``: Use ``spec.instance-id`` instead. Deprecated since v1.8.
* ``spec.eni.min-allocate``: Use ``spec.ipam.min-allocate`` instead. Deprecated since v1.8.
* ``spec.eni.pre-allocate``: Use ``spec.ipam.pre-allocate`` instead. Deprecated since v1.8.
* ``spec.eni.max-above-watermark``: Use ``spec.ipam.max-above-watermark`` instead. Deprecated since v1.8.
* ``status.azure.interfaces[].GatewayIP``: Use ``status.azure.interfaces[].gateway`` instead. Deprecated since v1.10.

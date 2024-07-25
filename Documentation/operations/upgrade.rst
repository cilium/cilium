.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _admin_upgrade:

*************
Upgrade Guide
*************

.. _upgrade_general:

This upgrade guide is intended for Cilium running on Kubernetes. If you have
questions, feel free to ping us on `Cilium Slack`_.

.. include:: upgrade-warning.rst

.. _pre_flight:

Running pre-flight check (Required)
===================================

When rolling out an upgrade with Kubernetes, Kubernetes will first terminate the
pod followed by pulling the new image version and then finally spin up the new
image. In order to reduce the downtime of the agent and to prevent ``ErrImagePull``
errors during upgrade, the pre-flight check pre-pulls the new image version.
If you are running in :ref:`kubeproxy-free`
mode you must also pass on the Kubernetes API Server IP and /
or the Kubernetes API Server Port when generating the ``cilium-preflight.yaml``
file.

.. tabs::
  .. group-tab:: kubectl

    .. parsed-literal::

      helm template |CHART_RELEASE| \\
        --namespace=kube-system \\
        --set preflight.enabled=true \\
        --set agent=false \\
        --set operator.enabled=false \\
        > cilium-preflight.yaml
      kubectl create -f cilium-preflight.yaml

  .. group-tab:: Helm

    .. parsed-literal::

      helm install cilium-preflight |CHART_RELEASE| \\
        --namespace=kube-system \\
        --set preflight.enabled=true \\
        --set agent=false \\
        --set operator.enabled=false

  .. group-tab:: kubectl (kubeproxy-free)

    .. parsed-literal::

      helm template |CHART_RELEASE| \\
        --namespace=kube-system \\
        --set preflight.enabled=true \\
        --set agent=false \\
        --set operator.enabled=false \\
        --set k8sServiceHost=API_SERVER_IP \\
        --set k8sServicePort=API_SERVER_PORT \\
        > cilium-preflight.yaml
      kubectl create -f cilium-preflight.yaml

  .. group-tab:: Helm (kubeproxy-free)

    .. parsed-literal::

      helm install cilium-preflight |CHART_RELEASE| \\
        --namespace=kube-system \\
        --set preflight.enabled=true \\
        --set agent=false \\
        --set operator.enabled=false \\
        --set k8sServiceHost=API_SERVER_IP \\
        --set k8sServicePort=API_SERVER_PORT

After applying the ``cilium-preflight.yaml``, ensure that the number of READY
pods is the same number of Cilium pods running.

.. code-block:: shell-session

    $ kubectl get daemonset -n kube-system | sed -n '1p;/cilium/p'
    NAME                      DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR   AGE
    cilium                    2         2         2       2            2           <none>          1h20m
    cilium-pre-flight-check   2         2         2       2            2           <none>          7m15s

Once the number of READY pods are equal, make sure the Cilium pre-flight
deployment is also marked as READY 1/1. If it shows READY 0/1, consult the
:ref:`cnp_validation` section and resolve issues with the deployment before
continuing with the upgrade.

.. code-block:: shell-session

    $ kubectl get deployment -n kube-system cilium-pre-flight-check -w
    NAME                      READY   UP-TO-DATE   AVAILABLE   AGE
    cilium-pre-flight-check   1/1     1            0           12s

.. _cleanup_preflight_check:

Clean up pre-flight check
-------------------------

Once the number of READY for the preflight :term:`DaemonSet` is the same as the number
of cilium pods running and the preflight ``Deployment`` is marked as READY ``1/1``
you can delete the cilium-preflight and proceed with the upgrade.

.. tabs::
  .. group-tab:: kubectl

    .. code-block:: shell-session

      kubectl delete -f cilium-preflight.yaml

  .. group-tab:: Helm

    .. code-block:: shell-session

      helm delete cilium-preflight --namespace=kube-system

.. _upgrade_minor:

Upgrading Cilium
================

During normal cluster operations, all Cilium components should run the same
version. Upgrading just one of them (e.g., upgrading the agent without
upgrading the operator) could result in unexpected cluster behavior.
The following steps will describe how to upgrade all of the components from
one stable release to a later stable release.

.. include:: upgrade-warning.rst

Step 1: Upgrade to latest patch version
---------------------------------------

When upgrading from one minor release to another minor release, for example
1.x to 1.y, it is recommended to upgrade to the `latest patch release
<https://github.com/cilium/cilium#stable-releases>`__ for a Cilium release series first.
Upgrading to the latest patch release ensures the most seamless experience if a
rollback is required following the minor release upgrade. The upgrade guides
for previous versions can be found for each minor version at the bottom left
corner.

Step 2: Use Helm to Upgrade your Cilium deployment
--------------------------------------------------------------------------------------

:term:`Helm` can be used to either upgrade Cilium directly or to generate a new set of
YAML files that can be used to upgrade an existing deployment via ``kubectl``.
By default, Helm will generate the new templates using the default values files
packaged with each new release. You still need to ensure that you are
specifying the equivalent options as used for the initial deployment, either by
specifying a them at the command line or by committing the values to a YAML
file.

.. include:: ../installation/k8s-install-download-release.rst

To minimize datapath disruption during the upgrade, the
``upgradeCompatibility`` option should be set to the initial Cilium
version which was installed in this cluster.

.. tabs::
  .. group-tab:: kubectl

    Generate the required YAML file and deploy it:

    .. parsed-literal::

      helm template |CHART_RELEASE| \\
        --set upgradeCompatibility=1.X \\
        --namespace kube-system \\
        > cilium.yaml
      kubectl apply -f cilium.yaml

  .. group-tab:: Helm

    Deploy Cilium release via Helm:

    .. parsed-literal::

      helm upgrade cilium |CHART_RELEASE| \\
        --namespace=kube-system \\
        --set upgradeCompatibility=1.X

.. note::

   Instead of using ``--set``, you can also save the values relative to your
   deployment in a YAML file and use it to regenerate the YAML for the latest
   Cilium version. Running any of the previous commands will overwrite
   the existing cluster's :term:`ConfigMap` so it is critical to preserve any existing
   options, either by setting them at the command line or storing them in a
   YAML file, similar to:

   .. code-block:: yaml

      agent: true
      upgradeCompatibility: "1.8"
      ipam:
        mode: "kubernetes"
      k8sServiceHost: "API_SERVER_IP"
      k8sServicePort: "API_SERVER_PORT"
      kubeProxyReplacement: "true"

   You can then upgrade using this values file by running:

   .. parsed-literal::

      helm upgrade cilium |CHART_RELEASE| \\
        --namespace=kube-system \\
        -f my-values.yaml

When upgrading from one minor release to another minor release using
``helm upgrade``, do *not* use Helm's ``--reuse-values`` flag.
The ``--reuse-values`` flag ignores any newly introduced values present in
the new release and thus may cause the Helm template to render incorrectly.
Instead, if you want to reuse the values from your existing installation,
save the old values in a values file, check the file for any renamed or
deprecated values, and then pass it to the ``helm upgrade`` command as
described above. You can retrieve and save the values from an existing
installation with the following command:

.. code-block:: shell-session

  helm get values cilium --namespace=kube-system -o yaml > old-values.yaml

The ``--reuse-values`` flag may only be safely used if the Cilium chart version
remains unchanged, for example when ``helm upgrade`` is used to apply
configuration changes without upgrading Cilium.

Step 3: Rolling Back
--------------------

Occasionally, it may be necessary to undo the rollout because a step was missed
or something went wrong during upgrade. To undo the rollout run:

.. tabs::
  .. group-tab:: kubectl

    .. code-block:: shell-session

      kubectl rollout undo daemonset/cilium -n kube-system

  .. group-tab:: Helm

    .. code-block:: shell-session

      helm history cilium --namespace=kube-system
      helm rollback cilium [REVISION] --namespace=kube-system

This will revert the latest changes to the Cilium ``DaemonSet`` and return
Cilium to the state it was in prior to the upgrade.

.. note::

    When rolling back after new features of the new minor version have already
    been consumed, consult the :ref:`version_notes` to check and prepare for
    incompatible feature use before downgrading/rolling back. This step is only
    required after new functionality introduced in the new minor version has
    already been explicitly used by creating new resources or by opting into
    new features via the :term:`ConfigMap`.

.. _version_notes:
.. _upgrade_version_specifics:

Version Specific Notes
======================

This section details the upgrade notes specific to |CURRENT_RELEASE|. Read them
carefully and take the suggested actions before upgrading Cilium to |CURRENT_RELEASE|.
For upgrades to earlier releases, see the
:prev-docs:`upgrade notes to the previous version <operations/upgrade/#upgrade-notes>`.

The only tested upgrade and rollback path is between consecutive minor releases.
Always perform upgrades and rollbacks between one minor release at a time.
Additionally, always update to the latest patch release of your current version
before attempting an upgrade.

Tested upgrades are expected to have minimal to no impact on new and existing
connections matched by either no Network Policies, or L3/L4 Network Policies only.
Any traffic flowing via user space proxies (for example, because an L7 policy is
in place, or using Ingress/Gateway API) will be disrupted during upgrade. Endpoints
communicating via the proxy must reconnect to re-establish connections.

.. _current_release_required_changes:

.. _1.16_upgrade_notes:

1.16 Upgrade Notes
------------------

* Cilium Envoy DaemonSet is now enabled by default for new installation if the helm attribute
  ``envoy.enabled`` is not specified, for existing cluster, please set ``upgradeCompatibility``
  to 1.15 or earlier to keep the previous behavior. This change adds one additional Pod per Node,
  therefore Nodes at maximum Pod capacity will face an eviction of a single non-system critical
  Pod after upgrading.
* For Linux kernels of version 6.6 or newer, Cilium by default switches to tcx BPF links for
  attaching its tc BPF programs in the core datapath for better resiliency and performance.
  If your current setup has third-party old-style tc BPF users, then this option should be
  disabled via Helm through ``bpf.enableTCX=false`` in order to continue in old-style tc BPF
  attachment mode as before.
* Starting with Cilium 1.16 netkit is supported as a new datapath mode for Linux kernels of
  version 6.8 or newer. Cilium still continues to rely on veth devices by default. In case
  of interest to experiment with netkit, please consider the :ref:`performance_tuning` guide
  for instructions. An in-place replacement of veth to netkit is not possible.
* The implementation of ``toFQDNs`` selectors in policies has been overhauled to improve
  performance when many different IPs are observed for a selector: Instead of creating
  ``cidr`` identities for each allowed IP, IPs observed in DNS lookups are now labeled
  with the selectors ``toFQDNs`` matching them. This reduces tail latency significantly for
  FQDNs with a highly dynamic set of IPs, such as e.g. content delivery networks and
  cloud object storage services.
  Cilium automatically migrates its internal state for ``toFQDNs`` policy entries upon
  upgrade or downgrade. To avoid drops during upgrades in clusters with ``toFQDNs`` policies,
  it is required to run Cilium v1.15.6 or newer before upgrading to Cilium v1.16. If upgrading
  from an older Cilium version, temporary packet drops for connections allowed by ``toFQDNs``
  policies may occur during the initial endpoint regeneration on Cilium v1.16.
  Similarly, when downgrading from v1.16 to v1.15 or older, temporary drops may occur for
  such connections as well during initial endpoint regeneration on the downgraded version.
* The ``cilium-dbg status --verbose`` command health data may now show health reported on a non-leaf
  component under a leaf named ``reporter``. Health data tree branches will now also be sorted by
  the fully qualified health status identifier.
* L7 network policy with terminatingTLS will not load the key ``ca.crt`` even if it is present in the
  secret. This prevents Envoy from incorrectly requiring client certificates from pods when using TLS
  termination. To retain old behaviour for bug compatibility, please set ``--use-full-tls-context=true``.
* The built-in WireGuard userspace-mode fallback (Helm ``wireguard.userspaceFallback``) has been
  deprecated and will be removed in a future version of Cilium. Users of WireGuard transparent
  encryption are required to use a Linux kernel with WireGuard support going forward.
* Local Redirect Policy, when enabled with socket-based load-balancing, redirects traffic
  from policy-selected node-local backends destined to the policy's frontend, back to the
  node-local backends. To override this behavior, which is enabled by default, create
  local redirect policies with the ``skipRedirectFromBackend`` flag set to ``true``.
* Detection and reconfiguration on changes to native network devices and their addresses is now
  the default. Cilium will now load the native device BPF program onto devices that appear after
  Cilium has started. NodePort services are now available on addresses assigned after Cilium has
  started. The set of addresses to use for NodePort can be configured with the Helm option
  ``nodePort.addresses``.
  The related Helm option ``enableRuntimeDeviceDetection`` has been deprecated and will be
  removed in future release. The devices and the addresses Cilium considers the node's addresses
  can be inspected with the ``cilium-dbg statedb devices`` and ``cilium-dbg statedb node-addresses``
  commands.
* Service connections that use ``Direct-Server-Return`` and were established prior to Cilium v1.13.3
  will be disrupted, and need to be re-established.
* Cilium Operator now uses dynamic rate limiting based on cluster size for the CiliumEndpointSlice
  controller. The ``ces-rate-limits`` flag or the Helm value ``ciliumEndpointSlice.rateLimits`` can
  be used to supply a custom configuration. The following list of flags for static and dynamic rate
  limits have been deprecated and their usage will be ignored:
  ``ces-write-qps-limit``, ``ces-write-qps-burst``, ``ces-enable-dynamic-rate-limit``,
  ``ces-dynamic-rate-limit-nodes``, ``ces-dynamic-rate-limit-qps-limit``,
  ``ces-dynamic-rate-limit-qps-burst``
* Metrics ``policy_regeneration_total`` and
  ``policy_regeneration_time_stats_seconds`` have been deprecated in favor of
  ``endpoint_regenerations_total`` and
  ``endpoint_regeneration_time_stats_seconds``, respectively.
* The Cilium cluster name is now validated to consist of at most 32 lower case
  alphanumeric characters and '-', start and end with an alphanumeric character.
  Validation can be currently bypassed configuring ``upgradeCompatibility`` to
  v1.15 or earlier, but will be strictly enforced starting from Cilium v1.17.
* Certain invalid CiliumNetworkPolicies that have always been ignored will now be rejected by the apiserver.
  Specifically, policies with multiple L7 protocols on the same port, over 40 port rules, or over
  40 ICMP rules will now have server-side validation.
* Cilium could previously be run in a configuration where the Etcd instances
  that distribute Cilium state between nodes would be managed in pod network by
  Cilium itself. This support was complicated and error prone, so the support
  is now deprecated. The following guide provides alternatives for running
  Cilium with Etcd: :ref:`k8s_install_etcd`.
* Cilium now respects the port specified as part of the etcd configuration, rather
  than defaulting it to that of the service when the address matches a Kubernetes
  service DNS name. Additionally, Kubernetes service DNS name to ClusterIP
  translation is now automatically enabled for etcd (if necessary); the
  ``etcd.operator`` ``kvstore-opt`` option is now a no-op and has been removed.
* KVStoreMesh is now enabled by default in Clustermesh.
  If you want to disable KVStoreMesh, set Helm value ``clustermesh.apiserver.kvstoremesh.enabled=false``
  explicitly during the upgrade.
* With the default enablement of KVStoreMesh, if you use :ref:`external workloads <external_workloads>`,
  ensure that your cluster has a Cluster name and ID specified before upgrading.
  Alternatively, you can explicitly opt out of KVStoreMesh.
* Gateway API GRPCRoute which is moved from ``v1alpha2`` to ``v1``. Please install new GRPCRoute CRD and migrate
  your resources from ``v1alpha2`` to ``v1`` version.
* The default value of of ``CiliumLoadBalancerIPPool.spec.allowFirstLastIPs`` has been changed to ``yes``.
  This means that unless explicitly configured otherwise, the first and last IP addresses of the IP pool
  are available for allocation. If you rely on the previous behavior, you should explicitly set
  ``allowFirstLastIPs: no`` in your IP pool configuration before the upgrade.
* The ``CiliumLoadBalancerIPPool.spec.cidrs`` field has been deprecated in v1.15 favor of 
  ``CiliumLoadBalancerIPPool.spec.blocks``. As of v1.15 both fields have the same behavior. The
  ``cidrs`` field will be removed in v1.16. Please update your IP pool configurations to use
  ``blocks`` instead of ``cidrs`` before upgrading.
* For IPsec, the use of per-tunnel keys is mandatory, via the use of the ``+``
  sign in the secret. See the :ref:`encryption_ipsec` guide for more
  information.
* ``CiliumNetworkPolicy`` changed the semantics of the empty non-nil slice.
  For an Ingress CNP, an empty slice in one of the fields ``fromEndpoints``, ``fromCIDR``,
  ``fromCIDRSet`` and ``fromEntities`` will not select any identity, thus falling back to
  default deny for an allow policy. Similarly, for an Egress CNP, an empty slice in one of
  the fields ``toEndpoints``, ``toCIDR``, ``toCIDRSet`` and ``toEntities`` will not select
  any identity either. Additionally, the behaviour of a CNP with ``toCIDRSet`` or
  ``fromCIDRSet`` selectors using ``cidrGroupRef`` targeting only non-existent CIDR groups
  was changed from allow-all to deny-all to align with the new semantics.

Removed Options
~~~~~~~~~~~~~~~

* The unused flag ``sidecar-istio-proxy-image`` has been removed.
* The flag ``endpoint-status`` has been removed.
  More information can be found in the following Helm upgrade notes.
* The ``ip-allocation-timeout`` flag (which provided a time limit on blocking
  CIDR identity allocations) has been removed. CIDR identity allocation
  now always happens asynchronously, therefore making this timeout obsolete.
* The deprecated flag ``enable-remote-node-identity`` has been removed.
  More information can be found in the following Helm upgrade notes.
* The deprecated flag ``install-egress-gateway-routes`` has been removed.

Deprecated Options
~~~~~~~~~~~~~~~~~~

* The ``clustermesh-ip-identities-sync-timeout`` flag has been deprecated in
  favor of ``clustermesh-sync-timeout``, and will be removed in Cilium 1.17.

Helm Options
~~~~~~~~~~~~

* Deprecated Helm option encryption.{keyFile,mountPath,secretName,interface} are removed
  in favor of encryption.ipsec.*.
* Deprecated options ``proxy.prometheus.enabled`` and ``proxy.prometheus.port`` have been removed.
  Please use ``envoy.prometheus.enabled`` and ``envoy.prometheus.port`` instead.
* The unused Helm option ``proxy.sidecarImageRegex`` has been removed.
* The Helm option ``endpointStatus`` has been removed. Instead of relying on additional statuses in CiliumEndpoints CRD,
  please rely on Cilium's metrics to monitor status of endpoints. Example metrics include: ``cilium_policy``, ``cilium_policy_endpoint_enforcement_status``,
  ``cilium_controllers_failing`` and ``cilium_endpoint_state``.
  More detailed information about specific endpoint status information is still available through ``cilium-dbg endpoint get``.
* The deprecated Helm option ``remoteNodeIdentity`` has been removed. This should have no impact on users who used the previous default
  value of ``true``: Remote nodes will now always use ``remote-node`` identity. If you have network policies based on
  ``enable-remote-node-identity=false`` make sure to update them.
* The clustermesh-apiserver ``podSecurityContext`` and ``securityContext`` settings now
  default to drop all capabilities and run as non-root user.
* Deprecated Helm option ``containerRuntime.integration`` is removed. If you are using crio, please check :ref:`crio-instructions`.
* Helm option ``enableRuntimeDeviceDetection`` is now deprecated and is a no-op.
* The IP addresses on which to expose NodePort services can now be configured with ``nodePort.addresses``. Prior to this, Cilium only
  exposed NodePort services on the first (preferably private) IPv4 and IPv6 address of each device.
* Helm option ``enableCiliumEndpointSlice`` has been deprecated and will be removed in a future release.
  The option has been replaced by ``ciliumEndpointSlice.enabled``.
* The Helm option for deploying a managed etcd instance via ``etcd.managed``
  and other related Helm configurations have been removed.
* The Clustermesh option ``clustermesh.apiserver.kvstoremesh.enabled`` is now set to ``true`` by default.
  To disable KVStoreMesh, set ``clustermesh.apiserver.kvstoremesh.enabled=false`` explicitly during the upgrade.

Added Metrics
~~~~~~~~~~~~~

* ``cilium_identity_label_sources`` is a new metric which counts the number of
  identities with per label source. This is particularly useful to further break
  down the source of local identities by having separate metrics for ``fqdn``
  and ``cidr`` labels.
* ``cilium_fqdn_selectors`` is a new metric counting the number of ingested
  ``toFQDNs`` selectors.

Removed Metrics
~~~~~~~~~~~~~~~

The following deprecated metrics were removed:

* ``cilium_ces_sync_errors_total``

Changed Metrics
~~~~~~~~~~~~~~~

* The ``cilium_api_limiter_processed_requests_total`` has now label ``return_code`` to specify the http code of the request.

.. _upgrade_cilium_cli_helm_mode:

Cilium CLI
~~~~~~~~~~

Upgrade Cilium CLI to `v0.15.0 <https://github.com/cilium/cilium-cli/releases/tag/v0.15.0>`_
or later to switch to `Helm installation mode <https://github.com/cilium/cilium-cli#helm-installation-mode>`_
to install and manage Cilium v1.16. Classic installation mode is **not**
supported with Cilium v1.16.

Helm and classic mode installations are not compatible with each other. Do not
use Cilium CLI in Helm mode to manage classic mode installations, and vice versa.

To migrate a classic mode Cilium installation to Helm mode, you need to
uninstall Cilium using classic mode Cilium CLI, and then re-install Cilium
using Helm mode Cilium CLI.

Advanced
========

Upgrade Impact
--------------

Upgrades are designed to have minimal impact on your running deployment.
Networking connectivity, policy enforcement and load balancing will remain
functional in general. The following is a list of operations that will not be
available during the upgrade:

* API-aware policy rules are enforced in user space proxies and are
  running as part of the Cilium pod. Upgrading Cilium causes the proxy to
  restart, which results in a connectivity outage and causes the connection to reset.

* Existing policy will remain effective but implementation of new policy rules
  will be postponed to after the upgrade has been completed on a particular
  node.

* Monitoring components such as ``cilium-dbg monitor`` will experience a brief
  outage while the Cilium pod is restarting. Events are queued up and read
  after the upgrade. If the number of events exceeds the event buffer size,
  events will be lost.


.. _upgrade_configmap:

Rebasing a ConfigMap
--------------------

This section describes the procedure to rebase an existing :term:`ConfigMap` to the
template of another version.

Export the current ConfigMap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

        $ kubectl get configmap -n kube-system cilium-config -o yaml --export > cilium-cm-old.yaml
        $ cat ./cilium-cm-old.yaml
        apiVersion: v1
        data:
          clean-cilium-state: "false"
          debug: "true"
          disable-ipv4: "false"
          etcd-config: |-
            ---
            endpoints:
            - https://192.168.60.11:2379
            #
            # In case you want to use TLS in etcd, uncomment the 'trusted-ca-file' line
            # and create a kubernetes secret by following the tutorial in
            # https://cilium.link/etcd-config
            trusted-ca-file: '/var/lib/etcd-secrets/etcd-client-ca.crt'
            #
            # In case you want client to server authentication, uncomment the following
            # lines and add the certificate and key in cilium-etcd-secrets below
            key-file: '/var/lib/etcd-secrets/etcd-client.key'
            cert-file: '/var/lib/etcd-secrets/etcd-client.crt'
        kind: ConfigMap
        metadata:
          creationTimestamp: null
          name: cilium-config
          selfLink: /api/v1/namespaces/kube-system/configmaps/cilium-config


In the :term:`ConfigMap` above, we can verify that Cilium is using ``debug`` with
``true``, it has a etcd endpoint running with `TLS <https://etcd.io/docs/latest/op-guide/security/>`_,
and the etcd is set up to have `client to server authentication <https://etcd.io/docs/latest/op-guide/security/#example-2-client-to-server-authentication-with-https-client-certificates>`_.

Generate the latest ConfigMap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: shell-session

    helm template cilium \
      --namespace=kube-system \
      --set agent.enabled=false \
      --set config.enabled=true \
      --set operator.enabled=false \
      > cilium-configmap.yaml

Add new options
~~~~~~~~~~~~~~~

Add the new options manually to your old :term:`ConfigMap`, and make the necessary
changes.

In this example, the ``debug`` option is meant to be kept with ``true``, the
``etcd-config`` is kept unchanged, and ``monitor-aggregation`` is a new
option, but after reading the :ref:`version_notes` the value was kept unchanged
from the default value.

After making the necessary changes, the old :term:`ConfigMap` was migrated with the
new options while keeping the configuration that we wanted:

::

        $ cat ./cilium-cm-old.yaml
        apiVersion: v1
        data:
          debug: "true"
          disable-ipv4: "false"
          # If you want to clean cilium state; change this value to true
          clean-cilium-state: "false"
          monitor-aggregation: "medium"
          etcd-config: |-
            ---
            endpoints:
            - https://192.168.60.11:2379
            #
            # In case you want to use TLS in etcd, uncomment the 'trusted-ca-file' line
            # and create a kubernetes secret by following the tutorial in
            # https://cilium.link/etcd-config
            trusted-ca-file: '/var/lib/etcd-secrets/etcd-client-ca.crt'
            #
            # In case you want client to server authentication, uncomment the following
            # lines and add the certificate and key in cilium-etcd-secrets below
            key-file: '/var/lib/etcd-secrets/etcd-client.key'
            cert-file: '/var/lib/etcd-secrets/etcd-client.crt'
        kind: ConfigMap
        metadata:
          creationTimestamp: null
          name: cilium-config
          selfLink: /api/v1/namespaces/kube-system/configmaps/cilium-config

Apply new ConfigMap
~~~~~~~~~~~~~~~~~~~

After adding the options, manually save the file with your changes and install
the :term:`ConfigMap` in the ``kube-system`` namespace of your cluster.

.. code-block:: shell-session

        $ kubectl apply -n kube-system -f ./cilium-cm-old.yaml

As the :term:`ConfigMap` is successfully upgraded we can start upgrading Cilium
``DaemonSet`` and ``RBAC`` which will pick up the latest configuration from the
:term:`ConfigMap`.


Migrating from kvstore-backed identities to Kubernetes CRD-backed identities
----------------------------------------------------------------------------

Beginning with cilium 1.6, Kubernetes CRD-backed security identities can be
used for smaller clusters. Along with other changes in 1.6 this allows
kvstore-free operation if desired. It is possible to migrate identities from an
existing kvstore deployment to CRD-backed identities. This minimizes
disruptions to traffic as the update rolls out through the cluster.

Affected versions
~~~~~~~~~~~~~~~~~

* Cilium 1.6 deployments using kvstore-backend identities

Mitigation
~~~~~~~~~~

When identities change, existing connections can be disrupted while cilium
initializes and synchronizes with the shared identity store. The disruption
occurs when new numeric identities are used for existing pods on some instances
and others are used on others. When converting to CRD-backed identities, it is
possible to pre-allocate CRD identities so that the numeric identities match
those in the kvstore. This allows new and old cilium instances in the rollout
to agree.

The steps below show an example of such a migration. It is safe to re-run the
command if desired. It will identify already allocated identities or ones that
cannot be migrated. Note that identity ``34815`` is migrated, ``17003`` is
already migrated, and ``11730`` has a conflict and a new ID allocated for those
labels.

The steps below assume a stable cluster with no new identities created during
the rollout. Once a cilium using CRD-backed identities is running, it may begin
allocating identities in a way that conflicts with older ones in the kvstore.

The cilium preflight manifest requires etcd support and can be built with:

.. code-block:: shell-session

    helm template cilium \
      --namespace=kube-system \
      --set preflight.enabled=true \
      --set agent.enabled=false \
      --set config.enabled=false \
      --set operator.enabled=false \
      --set etcd.enabled=true \
      --set etcd.ssl=true \
      > cilium-preflight.yaml
    kubectl create -f cilium-preflight.yaml


Example migration
~~~~~~~~~~~~~~~~~

.. code-block:: shell-session

      $ kubectl exec -n kube-system cilium-pre-flight-check-1234 -- cilium-dbg preflight migrate-identity
      INFO[0000] Setting up kvstore client
      INFO[0000] Connecting to etcd server...                  config=/var/lib/cilium/etcd-config.yml endpoints="[https://192.168.60.11:2379]" subsys=kvstore
      INFO[0000] Setting up kubernetes client
      INFO[0000] Establishing connection to apiserver          host="https://192.168.60.11:6443" subsys=k8s
      INFO[0000] Connected to apiserver                        subsys=k8s
      INFO[0000] Got lease ID 29c66c67db8870c8                 subsys=kvstore
      INFO[0000] Got lock lease ID 29c66c67db8870ca            subsys=kvstore
      INFO[0000] Successfully verified version of etcd endpoint  config=/var/lib/cilium/etcd-config.yml endpoints="[https://192.168.60.11:2379]" etcdEndpoint="https://192.168.60.11:2379" subsys=kvstore version=3.3.13
      INFO[0000] CRD (CustomResourceDefinition) is installed and up-to-date  name=CiliumNetworkPolicy/v2 subsys=k8s
      INFO[0000] Updating CRD (CustomResourceDefinition)...    name=v2.CiliumEndpoint subsys=k8s
      INFO[0001] CRD (CustomResourceDefinition) is installed and up-to-date  name=v2.CiliumEndpoint subsys=k8s
      INFO[0001] Updating CRD (CustomResourceDefinition)...    name=v2.CiliumNode subsys=k8s
      INFO[0002] CRD (CustomResourceDefinition) is installed and up-to-date  name=v2.CiliumNode subsys=k8s
      INFO[0002] Updating CRD (CustomResourceDefinition)...    name=v2.CiliumIdentity subsys=k8s
      INFO[0003] CRD (CustomResourceDefinition) is installed and up-to-date  name=v2.CiliumIdentity subsys=k8s
      INFO[0003] Listing identities in kvstore
      INFO[0003] Migrating identities to CRD
      INFO[0003] Skipped non-kubernetes labels when labelling ciliumidentity. All labels will still be used in identity determination  labels="map[]" subsys=crd-allocator
      INFO[0003] Skipped non-kubernetes labels when labelling ciliumidentity. All labels will still be used in identity determination  labels="map[]" subsys=crd-allocator
      INFO[0003] Skipped non-kubernetes labels when labelling ciliumidentity. All labels will still be used in identity determination  labels="map[]" subsys=crd-allocator
      INFO[0003] Migrated identity                             identity=34815 identityLabels="k8s:class=tiefighter;k8s:io.cilium.k8s.policy.cluster=default;k8s:io.cilium.k8s.policy.serviceaccount=default;k8s:io.kubernetes.pod.namespace=default;k8s:org=empire;"
      WARN[0003] ID is allocated to a different key in CRD. A new ID will be allocated for the this key  identityLabels="k8s:class=deathstar;k8s:io.cilium.k8s.policy.cluster=default;k8s:io.cilium.k8s.policy.serviceaccount=default;k8s:io.kubernetes.pod.namespace=default;k8s:org=empire;" oldIdentity=11730
      INFO[0003] Reusing existing global key                   key="k8s:class=deathstar;k8s:io.cilium.k8s.policy.cluster=default;k8s:io.cilium.k8s.policy.serviceaccount=default;k8s:io.kubernetes.pod.namespace=default;k8s:org=empire;" subsys=allocator
      INFO[0003] New ID allocated for key in CRD               identity=17281 identityLabels="k8s:class=deathstar;k8s:io.cilium.k8s.policy.cluster=default;k8s:io.cilium.k8s.policy.serviceaccount=default;k8s:io.kubernetes.pod.namespace=default;k8s:org=empire;" oldIdentity=11730
      INFO[0003] ID was already allocated to this key. It is already migrated  identity=17003 identityLabels="k8s:class=xwing;k8s:io.cilium.k8s.policy.cluster=default;k8s:io.cilium.k8s.policy.serviceaccount=default;k8s:io.kubernetes.pod.namespace=default;k8s:org=alliance;"

.. note::

    It is also possible to use the ``--k8s-kubeconfig-path``  and ``--kvstore-opt``
    ``cilium`` CLI options with the preflight command. The default is to derive the
    configuration as cilium-agent does.

  .. code-block:: shell-session

        cilium preflight migrate-identity --k8s-kubeconfig-path /var/lib/cilium/cilium.kubeconfig --kvstore etcd --kvstore-opt etcd.config=/var/lib/cilium/etcd-config.yml

Once the migration is complete, confirm the endpoint identities match by listing the endpoints stored in CRDs and in etcd:

.. code-block:: shell-session

      $ kubectl get ciliumendpoints -A # new CRD-backed endpoints
      $ kubectl exec -n kube-system cilium-1234 -- cilium-dbg endpoint list # existing etcd-backed endpoints

Clearing CRD identities
~~~~~~~~~~~~~~~~~~~~~~~

If a migration has gone wrong, it possible to start with a clean slate. Ensure that no cilium instances are running with identity-allocation-mode crd and execute:

.. code-block:: shell-session

      $ kubectl delete ciliumid --all

.. _cnp_validation:

CNP Validation
--------------

Running the CNP Validator will make sure the policies deployed in the cluster
are valid. It is important to run this validation before an upgrade so it will
make sure Cilium has a correct behavior after upgrade. Avoiding doing this
validation might cause Cilium from updating its ``NodeStatus`` in those invalid
Network Policies as well as in the worst case scenario it might give a false
sense of security to the user if a policy is badly formatted and Cilium is not
enforcing that policy due a bad validation schema. This CNP Validator is
automatically executed as part of the pre-flight check :ref:`pre_flight`.

Start by deployment the ``cilium-pre-flight-check`` and check if the
``Deployment`` shows READY 1/1, if it does not check the pod logs.

.. code-block:: shell-session

      $ kubectl get deployment -n kube-system cilium-pre-flight-check -w
      NAME                      READY   UP-TO-DATE   AVAILABLE   AGE
      cilium-pre-flight-check   0/1     1            0           12s

      $ kubectl logs -n kube-system deployment/cilium-pre-flight-check -c cnp-validator --previous
      level=info msg="Setting up kubernetes client"
      level=info msg="Establishing connection to apiserver" host="https://172.20.0.1:443" subsys=k8s
      level=info msg="Connected to apiserver" subsys=k8s
      level=info msg="Validating CiliumNetworkPolicy 'default/cidr-rule': OK!
      level=error msg="Validating CiliumNetworkPolicy 'default/cnp-update': unexpected validation error: spec.labels: Invalid value: \"string\": spec.labels in body must be of type object: \"string\""
      level=error msg="Found invalid CiliumNetworkPolicy"

In this example, we can see the ``CiliumNetworkPolicy`` in the ``default``
namespace with the name ``cnp-update`` is not valid for the Cilium version we
are trying to upgrade. In order to fix this policy we need to edit it, we can
do this by saving the policy locally and modify it. For this example it seems
the ``.spec.labels`` has set an array of strings which is not correct as per
the official schema.

.. code-block:: shell-session

      $ kubectl get cnp -n default cnp-update -o yaml > cnp-bad.yaml
      $ cat cnp-bad.yaml
        apiVersion: cilium.io/v2
        kind: CiliumNetworkPolicy
        [...]
        spec:
          endpointSelector:
            matchLabels:
              id: app1
          ingress:
          - fromEndpoints:
            - matchLabels:
                id: app2
            toPorts:
            - ports:
              - port: "80"
                protocol: TCP
          labels:
          - custom=true
        [...]

To fix this policy we need to set the ``.spec.labels`` with the right format and
commit these changes into Kubernetes.

.. code-block:: shell-session

      $ cat cnp-bad.yaml
        apiVersion: cilium.io/v2
        kind: CiliumNetworkPolicy
        [...]
        spec:
          endpointSelector:
            matchLabels:
              id: app1
          ingress:
          - fromEndpoints:
            - matchLabels:
                id: app2
            toPorts:
            - ports:
              - port: "80"
                protocol: TCP
          labels:
          - key: "custom"
            value: "true"
        [...]
      $
      $ kubectl apply -f ./cnp-bad.yaml

After applying the fixed policy we can delete the pod that was validating the
policies so that Kubernetes creates a new pod immediately to verify if the fixed
policies are now valid.

.. code-block:: shell-session

      $ kubectl delete pod -n kube-system -l k8s-app=cilium-pre-flight-check-deployment
      pod "cilium-pre-flight-check-86dfb69668-ngbql" deleted
      $ kubectl get deployment -n kube-system cilium-pre-flight-check
      NAME                      READY   UP-TO-DATE   AVAILABLE   AGE
      cilium-pre-flight-check   1/1     1            1           55m
      $ kubectl logs -n kube-system deployment/cilium-pre-flight-check -c cnp-validator
      level=info msg="Setting up kubernetes client"
      level=info msg="Establishing connection to apiserver" host="https://172.20.0.1:443" subsys=k8s
      level=info msg="Connected to apiserver" subsys=k8s
      level=info msg="Validating CiliumNetworkPolicy 'default/cidr-rule': OK!
      level=info msg="Validating CiliumNetworkPolicy 'default/cnp-update': OK!
      level=info msg="All CCNPs and CNPs valid!"

Once they are valid you can continue with the upgrade process. :ref:`cleanup_preflight_check`

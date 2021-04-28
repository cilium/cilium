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
questions, feel free to ping us on the `Slack channel`.

.. include:: upgrade-warning.rst

.. _pre_flight:

Running pre-flight check (Required)
===================================

When rolling out an upgrade with Kubernetes, Kubernetes will first terminate the
pod followed by pulling the new image version and then finally spin up the new
image. In order to reduce the downtime of the agent and to prevent ErrImagePull
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

Once the number of READY pods are the equal, make sure the Cilium pre-flight
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

Once the number of READY for the preflight `DaemonSet` is the same as the number
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

.. include:: upgrade-warning.rst

Step 1: Upgrade to latest micro version (Recommended)
-----------------------------------------------------

When upgrading from one minor release to another minor release, for example
1.x to 1.y, it is recommended to upgrade to the latest micro release for a
Cilium release series first. The latest micro releases for each supported
version of Cilium are `here <https://github.com/cilium/cilium#stable-releases>`_.
Upgrading to the latest micro release ensures the most seamless experience if a
rollback is required following the minor release upgrade.

Step 2: Use Helm to Upgrade your Cilium deployment
--------------------------------------------------------------------------------------

`Helm` can be used to either upgrade Cilium directly or to generate a new set of
YAML files that can be used to upgrade an existing deployment via ``kubectl``.
By default, Helm will generate the new templates using the default values files
packaged with each new release. You still need to ensure that you are
specifying the equivalent options as used for the initial deployment, either by
specifying a them at the command line or by committing the values to a YAML
file. The `1.9_helm_options` section describes how to determine the exact
options that should be set based on the initial options used to install Cilium.

.. include:: ../gettingstarted/k8s-install-download-release.rst

To minimize datapath disruption during the upgrade, the
``upgradeCompatibility`` option should be set to the initial Cilium
version which was installed in this cluster. Valid options are:

* ``1.7`` if the initial install was Cilium 1.7.x or earlier.
* ``1.8`` if the initial install was Cilium 1.8.x.
* ``1.9`` if the initial install was Cilium 1.9.x.

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

   Make sure that you are using the equivalent options as for the initial
   deployment. Cilium 1.9 renamed many of the Helm options to better support
   specifying Cilium configuration via a ``values.yaml`` file. Consult the
   `1.9_helm_options` to determine the 1.9 equivalent options for options you
   previously specified when initially installing Cilium.

   For example, an 1.8 installation with the following options::

      --namespace=kube-system \\
      --set global.k8sServiceHost=API_SERVER_IP \\
      --set global.k8sServicePort=API_SERVER_PORT \\
      --set config.ipam=kubernetes \\
      --set global.kubeProxyReplacement=strict


   Can be upgraded using the options below::

      --namespace=kube-system \\
      --set upgradeCompatibility=1.8 \\
      --set k8sServiceHost=API_SERVER_IP \\
      --set k8sServicePort=API_SERVER_PORT \\
      --set ipam.mode=kubernetes \\
      --set kubeProxyReplacement=strict

   Instead of using ``--set``, you can also save the values relative to your
   deployment in a YAML file and use it to regenerate the YAML for the latest
   Cilium version. Running any of the previous commands will overwrite
   the existing cluster's `ConfigMap` so it is critical to preserve any existing
   options, either by setting them at the command line or storing them in a
   YAML file, similar to:

   .. code-block:: yaml

      agent: true
      upgradeCompatibility: "1.8"
      ipam:
        mode: "kubernetes"
      k8sServiceHost: "API_SERVER_IP"
      k8sServicePort: "API_SERVER_PORT"
      kubeProxyReplacement: "strict"

   You can then upgrade using this values file by running:

   .. parsed-literal::

      helm upgrade cilium |CHART_RELEASE| \\
        --namespace=kube-system \\
        -f my-values.yaml

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
    new features via the `ConfigMap`.

.. _version_notes:
.. _upgrade_version_specifics:

Version Specific Notes
======================

This section documents the specific steps required for upgrading from one
version of Cilium to another version of Cilium. There are particular version
transitions which are suggested by the Cilium developers to avoid known issues
during upgrade, then subsequently there are sections for specific upgrade
transitions, ordered by version.

The table below lists suggested upgrade transitions, from a specified current
version running in a cluster to a specified target version. If a specific
combination is not listed in the table below, then it may not be safe. In that
case, consider staging the upgrade, for example upgrading from ``1.1.x`` to the
latest ``1.1.y`` release before subsequently upgrading to ``1.2.z``.

+-----------------------+-----------------------+-------------------------+---------------------------+
| Current version       | Target version        | L3 impact               | L7 impact                 |
+=======================+=======================+=========================+===========================+
| ``>=1.7.1``           | ``1.8.y``             | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.8.x``             | ``1.9.y``             | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+-------------------------+---------------------------+

Annotations:

#. **Clients must reconnect**: Any traffic flowing via a proxy (for example,
   because an L7 policy is in place) will be disrupted during upgrade.
   Endpoints communicating via the proxy must reconnect to re-establish
   connections.

.. _current_release_required_changes:

.. _1.10_upgrade_notes:

1.10 Upgrade Notes
------------------

* Cilium has bumped the minimal Kubernetes version supported to v1.16.0.
* When using the ENI-based IPAM in conjunction with the ``--eni-tags``, failures
  to create tags are treated as errors which will result in ENIs not being
  created. Ensure that the ``ec2:CreateTags`` IAM permissions are granted.
* Cilium now takes ownership of the ``/etc/cni/net.d/`` directory on the host
  by default. During agent startup, Cilium replaces all CNI configuration files
  containing the word ``cilium``, and non-Cilium CNI configuration files are
  renamed to ``*.cilium_bak``. During agent shutdown, all Cilium CNI configs
  are removed. To disable the ``*.cilium_bak`` behaviour, set the
  ``cni.exclusive=false`` Helm flag. To disable CNI config installation and
  removal altogether, set the ``cni.customConf=true`` Helm flag.
  This is useful for managing CNI configs externally.
  See https://github.com/cilium/cilium/pull/14192 for context and related issues.
* Helm option ``serviceAccounts.certgen`` is removed, please use ``serviceAccounts.clustermeshcertgen``
  for Clustermesh certificate generation and ``serviceAccounts.hubblecertgen`` for Hubble certificate generation.
* For AWS ENI IPAM mode, Cilium has changed the ``first-interface-index``
  default from ``1`` to ``0``. This means that pods will start using IPs of
  ``eth0`` instead of ``eth1``. This allows using the maximum number of IPs
  available on an instance by default. Be aware: Depending on your security
  groups configuration of the ``eth0`` interface, pods may be associated with a
  different security group all of a sudden. In order to stay with Cilium's
  current behavior, set the value to ``1`` in the ``CiliumNode`` resource.
* The legacy flannel integration has been deprecated. If you want to chain on
  top of flannel, use the standard chaining method.
* The default setting for ``kubeProxyReplacement`` has been changed from
  ``probe`` to ``disabled``. For any new installation, if you want to use
  kube-proxy replacement, set  ``kubeProxyReplacement`` to ``strict``.

Removed Metrics/Labels
~~~~~~~~~~~~~~~~~~~~~~

The following metrics have been removed:

* ``cilium_endpoint_regenerations`` is removed. Please use ``cilium_endpoint_regenerations_total`` instead.
* ``cilium_k8s_client_api_calls_counter`` is removed. Please use ``cilium_k8s_client_api_calls_total`` instead.
* ``cilium_identity_count`` is removed. Please use ``cilium_identity`` instead.
* ``cilium_policy_count`` is removed. Please use ``cilium_policy`` instead.
* ``cilium_policy_import_errors`` is removed. Please use ``cilium_policy_import_errors_total`` instead.
* ``cilium_datapath_errors_total`` is removed. Please use ``cilium_datapth_conntrack_dump_resets_total`` instead.
* Label ``mapName`` in ``cilium_bpf_map_ops_total`` is removed. Please use label ``map_name`` instead.
* Label ``eventType`` in ``cilium_nodes_all_events_received_total`` removed. Please use label ``event_type`` instead.
* Label ``responseCode`` in ``*api_duration_seconds`` removed. Please use label ``response_code`` instead.
* Label ``subnetId`` in ``cilium_operator_ipam_allocation_ops`` is removed. Please use label ``subnet_id`` instead.
* Label ``subnetId`` in ``cilium_operator_ipam_release_ops`` is removed. Please use label ``subnet_id`` instead.
* Label ``subnetId`` and ``availabilityZone`` in ``cilium_operator_ipam_available_ips_per_subnet`` are removed. Please
  use label ``subnet_id`` and ``availability_zone`` instead.

New Metrics
~~~~~~~~~~~

  * ``cilium_datapath_conntrack_dump_resets_total`` Number of conntrack dump resets. Happens when a BPF entry gets removed
    while dumping the map is in progress.

New Options
~~~~~~~~~~~

* ``enable-ipv6-masquerade``: This option can be used to enable/disable masquerading
  for IPv6 traffic. Currently the only mode supported is ``iptables`` with BPF based
  IPv6 masquerading in the roadmap.
* ``enable-ipv4-masquerade``: This option enables/disables masquerading for IPv4 traffic
  and has the same desired effect as ``masquerade`` option.
* ``cni.exclusive``: Use to toggle Cilium installing itself as the only available CNI
  plugin on all nodes.
* ``install-no-conntrack-iptables-rules``: This option, by default set to false,
  installs some extra Iptables rules to skip netfilter connection tracking on all
  pod traffic. Disabling connection tracking is only possible when Cilium is
  running in direct routing mode and is using the kube-proxy replacement.
  Moreover, this option cannot be enabled when Cilium is running in a managed
  Kubernetes environment or in a chained CNI setup.
* ``allocator-list-timeout``: This option configures the timeout value for listing
  allocator state before exiting (default 3m0s).
* With the deprecation of the legacy flannel integration, the options
  ``flannel-master-device`` and ``flannel-uninstall-on-exit`` have been removed.

Removed Options
~~~~~~~~~~~~~~~

* ``k8s-watcher-queue-size``: this option does not have any effect since 1.8 and
  is now removed.
* ``blacklist-conflicting-routes``: this option does not have any effect since
  1.9 and is now removed.
* ``device``: this option was deprecated in 1.9 in favor of ``devices`` and is
  now removed.
* ``crd-wait-timeout``: this option does not have any effect since 1.9 and is
  now removed.
* ``eni``: this option has been replaced by ``eni.enabled`` option.

Deprecated Options
~~~~~~~~~~~~~~~~~~

* ``etcd.managed``: The managed etcd mode is being deprecated. The option and
  all relevant code will be removed in 1.11. If you are using managed etcd, you
  will need to run & deploy the etcd-operator yourself.
* ``bpf-compile-debug``: This option does not have any effect since 1.10
  and is planned to be removed in 1.11.
* ``k8s-force-json-patch``: This option does not have any effect for
  environments running Kubernetes >= 1.13. Marked for removal in Cilium v1.11.
* ``masquerade``: With the introduction of IPv6 masquerading this option has
  been deprecated in favor of ``enable-ipv4-masquerade`` and is planned to
  be removed in 1.11. For 1.10 release this option will have the same effect as
  ``enable-ipv4-masquerade`` where both options must not be used simultaneously.
* ``skip-crd-creation``: This option does not have any effect since 1.10
  and is planned to be removed in 1.11.
* Helm options ``encryption.keyFile``, ``encryption.mountPath``,
  ``encryption.secretName`` and ``encryption.interface`` are now deprecated in
  favor of ``encryption.ipsec.keyFile``, ``encryption.ipsec.mountPath``,
  ``encryption.ipsec.secretName`` and ``encryption.ipsec.interface``.

.. _1.9_upgrade_notes:

1.9.1 Upgrade Notes
-------------------

* Helm option ``nodeSelector`` is removed, please use the option for respective component
  (e.g. ``operator.nodeSelector``, ``etcd.nodeSelector`` and ``preflight.nodeSelector``) instead.

1.9 Upgrade Notes
-----------------

* Cilium has bumped the minimal Kubernetes version supported to v1.12.0.
* Connections between Hubble server and Hubble Relay instances is now secured
  via mutual TLS (mTLS) by default. Users who have opted to enable Hubble Relay
  in v1.8 (a beta feature) will experience disruptions of the Hubble Relay
  service during the upgrade process.
  Users may opt to disable mTLS by using the following Helm options when
  upgrading (strongly discouraged):

  - ``hubble.tls.enabled=false``
  - ``hubble.tls.auto.enabled=false``
* Cilium has upgraded its CRDs to v1, from v1beta1. Users must
  `run the preflight checker <pre_flight>` to ensure that the custom resources
  installed inside the cluster are well-formed.
* The Cilium agent is now enforcing API rate limits for certain API calls. See
  :ref:`api_rate_limiting` for more information.
* Cilium Helm charts have been completely re-factored. Most of the values used
  to drive Helm charts have been re-scoped from global values to be part of a
  single Cilium Helm chart. When upgrading from a previous version of Cilium,
  the values will need to be provided using the new structure. In most cases the
  prefixes of ``global.``, ``agent.``, and ``config.`` can be dropped from the
  previously used value name. As an example, if you previously ran the command
  ``helm install --set global.ipv4.enabled=true`` you would now run ``helm
  install --set ipv4.enabled=true``. The following section calls out specific
  values where the prefix cannot be simply dropped followed by a full
  table of old and new Helm values.
* On Linux kernel v5.10 and above, running the agent with BPF kube-proxy replacement
  under direct routing operation as well as BPF-based masquerading will bypass
  subsystems like netfilter/iptables in the host namespace in order to significantly
  improve throughput and latency for the BPF datapath given routing is not performed
  in the host stack but directly in BPF instead. To opt-out from this behavior,
  the Helm option ``bpf.hostRouting=true`` can be used. If the underlying kernel
  does not implement the needed BPF features, then the agent will fallback and rely
  on host routing automatically.
* For the agent, operator, clustermesh-apiserver and hubble-relay, the gops listener
  has been mapped to fixed ports instead of port auto-binding. Meaning, the agent's
  gops server will listen on 9890, the operator on 9891, the clustermesh-apiserver on
  9892, and hubble-relay on port 9893 by default. If needed, the port can also be
  remapped for each through using the ``--gops-port`` flag.

.. _1.9_helm_options:

1.9 Helm options
~~~~~~~~~~~~~~~~

The following values have been renamed:

+----------------------------------------------+--------------------------------------------+
| <= v1.8.x Value                              | >= 1.9.x Renamed Value                     |
+==============================================+============================================+
| agent.enabled                                | agent                                      |
+----------------------------------------------+--------------------------------------------+
| config.bpfMasquerade                         | bpf.masquerade                             |
+----------------------------------------------+--------------------------------------------+
| config.bpfClockProbe                         | bpf.clockProbe                             |
+----------------------------------------------+--------------------------------------------+
| config.ipam                                  | ipam.mode                                  |
+----------------------------------------------+--------------------------------------------+
| global.operatorPrometheus.*                  | operator.prometheus.*                      |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.*                               | hubble.relay.*                             |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.numReplicas                     | hubble.relay.replicas                      |
+----------------------------------------------+--------------------------------------------+
| hubble-ui.*                                  | hubble.ui.*                                |
+----------------------------------------------+--------------------------------------------+
| operator.numReplicas                         | operator.replicas                          |
+----------------------------------------------+--------------------------------------------+
| global.nodePort.acceleration                 | loadBalancer.acceleration                  |
+----------------------------------------------+--------------------------------------------+
| global.nodePort.mode                         | loadBalancer.mode                          |
+----------------------------------------------+--------------------------------------------+

Full list of updated Helm values:

+----------------------------------------------+--------------------------------------------+
| <= v1.8.x Value                              | >= 1.9.x Value                             |
+==============================================+============================================+
| global.autoDirectNodeRoutes                  | autoDirectNodeRoutes                       |
+----------------------------------------------+--------------------------------------------+
| global.azure.enabled                         | azure.enabled                              |
+----------------------------------------------+--------------------------------------------+
| config.bpfClockProbe                         | bpf.clockProbe                             |
+----------------------------------------------+--------------------------------------------+
| global.bpf.ctAnyMax                          | bpf.ctAnyMax                               |
+----------------------------------------------+--------------------------------------------+
| global.bpf.ctTcpMax                          | bpf.ctTcpMax                               |
+----------------------------------------------+--------------------------------------------+
| global.bpf.lbMapMax                          | bpf.lbMapMax                               |
+----------------------------------------------+--------------------------------------------+
| config.bpf.mapDynamicSizeRatio               | bpf.mapDynamicSizeRatio                    |
+----------------------------------------------+--------------------------------------------+
| config.bpfMasquerade                         | bpf.masquerade                             |
+----------------------------------------------+--------------------------------------------+
| global.bpf.monitorAggregation                | bpf.monitorAggregation                     |
+----------------------------------------------+--------------------------------------------+
| global.bpf.monitorFlags                      | bpf.monitorFlags                           |
+----------------------------------------------+--------------------------------------------+
| global.bpf.monitorInterval                   | bpf.monitorInterval                        |
+----------------------------------------------+--------------------------------------------+
| global.bpf.natMax                            | bpf.natMax                                 |
+----------------------------------------------+--------------------------------------------+
| global.bpf.neighMax                          | bpf.neighMax                               |
+----------------------------------------------+--------------------------------------------+
| global.bpf.policyMapMax                      | bpf.policyMapMax                           |
+----------------------------------------------+--------------------------------------------+
| global.bpf.preallocateMaps                   | bpf.preallocateMaps                        |
+----------------------------------------------+--------------------------------------------+
| global.bpf.waitForMount                      | bpf.waitForMount                           |
+----------------------------------------------+--------------------------------------------+
| config.bpfMasquerade                         | bpf.masquerade                             |
+----------------------------------------------+--------------------------------------------+
| global.cleanBpfState                         | cleanBpfState                              |
+----------------------------------------------+--------------------------------------------+
| global.cleanState                            | cleanState                                 |
+----------------------------------------------+--------------------------------------------+
| global.cluster.id                            | cluster.id                                 |
+----------------------------------------------+--------------------------------------------+
| global.cluster.name                          | cluster.name                               |
+----------------------------------------------+--------------------------------------------+
| global.cni.binPath                           | cni.binPath                                |
+----------------------------------------------+--------------------------------------------+
| global.cni.chainingMode                      | cni.chainingMode                           |
+----------------------------------------------+--------------------------------------------+
| global.cni.confPath                          | cni.confPath                               |
+----------------------------------------------+--------------------------------------------+
| global.cni.customConf                        | cni.customConf                             |
+----------------------------------------------+--------------------------------------------+
| global.cni.hostConfDirMountPath              | cni.hostConfDirMountPath                   |
+----------------------------------------------+--------------------------------------------+
| global.cni.install                           | cni.install                                |
+----------------------------------------------+--------------------------------------------+
| config.crdWaitTimeout                        | crdWaitTimeout                             |
+----------------------------------------------+--------------------------------------------+
| config.enableCnpStatusUpdates                | enableCnpStatusUpdates                     |
+----------------------------------------------+--------------------------------------------+
| config.conntrackGCInterval                   | conntrackGCInterval                        |
+----------------------------------------------+--------------------------------------------+
| global.containerRuntime.integration          | containerRuntime.integration               |
+----------------------------------------------+--------------------------------------------+
| global.daemon.runPath                        | daemon.runPath                             |
+----------------------------------------------+--------------------------------------------+
| global.datapathMode                          | datapathMode                               |
+----------------------------------------------+--------------------------------------------+
| global.debug.enabled                         | debug.enabled                              |
+----------------------------------------------+--------------------------------------------+
| config.disableEnvoyVersionCheck              | disableEnvoyVersionCheck                   |
+----------------------------------------------+--------------------------------------------+
| global.egressMasqueradeInterfaces            | egressMasqueradeInterfaces                 |
+----------------------------------------------+--------------------------------------------+
| config.enableIdentityMark                    | enableIdentityMark                         |
+----------------------------------------------+--------------------------------------------+
| global.enableXTSocketFallback                | enableXTSocketFallback                     |
+----------------------------------------------+--------------------------------------------+
| agent.enabled                                | agent                                      |
+----------------------------------------------+--------------------------------------------+
| global.encryption.enabled                    | encryption.enabled                         |
+----------------------------------------------+--------------------------------------------+
| global.encryption.interface                  | encryption.interface                       |
+----------------------------------------------+--------------------------------------------+
| global.encryption.keyFile                    | encryption.keyFile                         |
+----------------------------------------------+--------------------------------------------+
| global.encryption.mountPath                  | encryption.mountPath                       |
+----------------------------------------------+--------------------------------------------+
| global.encryption.nodeEncryption             | encryption.nodeEncryption                  |
+----------------------------------------------+--------------------------------------------+
| global.encryption.secretName                 | encryption.secretName                      |
+----------------------------------------------+--------------------------------------------+
| global.endpointHealthChecking.enabled        | endpointHealthChecking.enabled             |
+----------------------------------------------+--------------------------------------------+
| global.endpointRoutes.enabled                | endpointRoutes.enabled                     |
+----------------------------------------------+--------------------------------------------+
| global.eni                                   | eni                                        |
+----------------------------------------------+--------------------------------------------+
| global. etcd.clusterDomain                   | etcd.clusterDomain                         |
+----------------------------------------------+--------------------------------------------+
| global.etcd.clusterSize                      | etcd.clusterSize                           |
+----------------------------------------------+--------------------------------------------+
| global.etcd.enabled                          | etcd.enabled                               |
+----------------------------------------------+--------------------------------------------+
| global.etcd.endpoints                        | etcd.endpoints                             |
+----------------------------------------------+--------------------------------------------+
| global.etcd.k8sService                       | etcd.k8sService                            |
+----------------------------------------------+--------------------------------------------+
| global.etcd.managed                          | etcd.managed                               |
+----------------------------------------------+--------------------------------------------+
| global.etcd.ssl                              | etcd.ssl                                   |
+----------------------------------------------+--------------------------------------------+
| global.externalIPs.enabled                   | externalIPs.enabled                        |
+----------------------------------------------+--------------------------------------------+
| global.fragmentTracking                      | fragmentTracking                           |
+----------------------------------------------+--------------------------------------------+
| global.gke.enabled                           | gke.enabled                                |
+----------------------------------------------+--------------------------------------------+
| config.healthChecking                        | healthChecking                             |
+----------------------------------------------+--------------------------------------------+
| global.healthPort                            | healthPort                                 |
+----------------------------------------------+--------------------------------------------+
| global.hostFirewall                          | hostFirewall                               |
+----------------------------------------------+--------------------------------------------+
| global.hostPort.enabled                      | hostPort.enabled                           |
+----------------------------------------------+--------------------------------------------+
| global.hostServices.enabled                  | hostServices.enabled                       |
+----------------------------------------------+--------------------------------------------+
| global.hostServices.protocols                | hostServices.protocols                     |
+----------------------------------------------+--------------------------------------------+
| global.hubble.enabled                        | hubble.enabled                             |
+----------------------------------------------+--------------------------------------------+
| global.hubble.eventQueueSize                 | hubble.eventQueueSize                      |
+----------------------------------------------+--------------------------------------------+
| global.hubble.flowBufferSize                 | hubble.flowBufferSize                      |
+----------------------------------------------+--------------------------------------------+
| global.hubble.listenAddress                  | hubble.listenAddress                       |
+----------------------------------------------+--------------------------------------------+
| global.hubble.metrics.enabled                | hubble.metrics.enabled                     |
+----------------------------------------------+--------------------------------------------+
| global.hubble.metrics.port                   | hubble.metrics.port                        |
+----------------------------------------------+--------------------------------------------+
| global.hubble.metrics.serviceMonitor.enabled | hubble.metrics.serviceMonitor.enabled      |
+----------------------------------------------+--------------------------------------------+
| global.hubble.metricsServer                  | hubble.metricsServer                       |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.dialTimeout                     | hubble.relay.dialTimeout                   |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.enabled                         | hubble.relay.enabled                       |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.image.pullPolicy                | hubble.relay.image.pullPolicy              |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.image.repository                | hubble.relay.image.repository              |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.image.tag                       | hubble.relay.image.tag                     |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.listenHost                      | hubble.relay.listenHost                    |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.listenPort                      | hubble.relay.listenPort                    |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.numReplicas                     | hubble.relay.replicas                      |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.retryTimeout                    | hubble.relay.retryTimeout                  |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.servicePort                     | hubble.relay.servicePort                   |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.sortBufferDrainTimeout          | hubble.relay.sortBufferDrainTimeout        |
+----------------------------------------------+--------------------------------------------+
| hubble-relay.sortBufferLenMax                | hubble.relay.sortBufferLenMax              |
+----------------------------------------------+--------------------------------------------+
| global.hubble.socketPath                     | hubble.socketPath                          |
+----------------------------------------------+--------------------------------------------+
| hubble-ui.enabled                            | hubble.ui.enabled                          |
+----------------------------------------------+--------------------------------------------+
| hubble-ui.image.pullPolicy                   | hubble.ui.frontend.image.pullPolicy        |
+----------------------------------------------+--------------------------------------------+
| hubble-ui.image.repository                   | hubble.ui.frontend.image.repository        |
+----------------------------------------------+--------------------------------------------+
| hubble-ui.image.tag                          | hubble.ui.frontend.image.tag               |
+----------------------------------------------+--------------------------------------------+
| hubble-ui.ingress.enabled                    | hubble.ui.ingress.enabled                  |
+----------------------------------------------+--------------------------------------------+
| hubble-ui.ingress.hosts                      | hubble.ui.ingress.hosts                    |
+----------------------------------------------+--------------------------------------------+
| hubble.-ui.ingress.path                      | hubble.ui.ingress.path                     |
+----------------------------------------------+--------------------------------------------+
| hubble-ui.ingress.tls                        | hubble.ui.ingress.tls                      |
+----------------------------------------------+--------------------------------------------+
| global.identityAllocationMode                | identityAllocationMode                     |
+----------------------------------------------+--------------------------------------------+
| config.identityChangeGracePeriod             | identityChangeGracePeriod                  |
+----------------------------------------------+--------------------------------------------+
| global.identityGCInterval                    | identityGCInterval                         |
+----------------------------------------------+--------------------------------------------+
| global.identityHeartbeatTimeout              | identityHeartbeatTimeout                   |
+----------------------------------------------+--------------------------------------------+
| global.pullPolicy                            | image.pullPolicy                           |
+----------------------------------------------+--------------------------------------------+
| agent.image                                  | image.repository                           |
+----------------------------------------------+--------------------------------------------+
| global.tag                                   | image.tag                                  |
+----------------------------------------------+--------------------------------------------+
| global.installIptablesRules                  | installIptablesRules                       |
+----------------------------------------------+--------------------------------------------+
| global.ipMasqAgent.enabled                   | ipMasqAgent.enabled                        |
+----------------------------------------------+--------------------------------------------+
| config.ipam                                  | ipam.mode                                  |
+----------------------------------------------+--------------------------------------------+
| global.ipam.operator.clusterPoolIPv4MaskSize | ipam.operator.clusterPoolIPv4MaskSize      |
+----------------------------------------------+--------------------------------------------+
| global.ipam.operator.clusterPoolIPv4PodCIDR  | ipam.operator.clusterPoolIPv4PodCIDR       |
+----------------------------------------------+--------------------------------------------+
| global.ipam.operator.clusterPoolIPv6MaskSize | ipam.operator.clusterPoolIPv6MaskSize      |
+----------------------------------------------+--------------------------------------------+
| global.ipam.operator.clusterPoolIPv6PodCIDR  | ipam.operator.clusterPoolIPv6PodCIDR       |
+----------------------------------------------+--------------------------------------------+
| global.iptablesLockTimeout                   | iptablesLockTimeout                        |
+----------------------------------------------+--------------------------------------------+
| global.ipv4.enabled                          | ipv4.enabled                               |
+----------------------------------------------+--------------------------------------------+
| global.ipv6.enabled                          | ipv6.enabled                               |
+----------------------------------------------+--------------------------------------------+
| global.ipvlan.enabled                        | ipvlan.enabled                             |
+----------------------------------------------+--------------------------------------------+
| global.ipvlan.masterDevice                   | ipvlan.masterDevice                        |
+----------------------------------------------+--------------------------------------------+
| global.k8sServiceHost                        | k8sServiceHost                             |
+----------------------------------------------+--------------------------------------------+
| global.k8sServicePort                        | k8sServicePort                             |
+----------------------------------------------+--------------------------------------------+
| global.k8s.requireIPv4PodCIDR                | k8s.requireIPv4PodCIDR                     |
+----------------------------------------------+--------------------------------------------+
| agent.keepDeprecatedLabels                   | keepDeprecatedLabels                       |
+----------------------------------------------+--------------------------------------------+
| agent.keepDeprecatedProbes                   | keepDeprecatedProbes                       |
+----------------------------------------------+--------------------------------------------+
| global.kubeProxyReplacement                  | kubeProxyReplacement                       |
+----------------------------------------------+--------------------------------------------+
| global.l7Proxy                               | l7Proxy                                    |
+----------------------------------------------+--------------------------------------------+
| config.labels                                | labels                                     |
+----------------------------------------------+--------------------------------------------+
| global.logSystemLoad                         | logSystemLoad                              |
+----------------------------------------------+--------------------------------------------+
| global.maglev.tableSize                      | maglev.tableSize                           |
+----------------------------------------------+--------------------------------------------+
| global.masquerade                            | masquerade                                 |
+----------------------------------------------+--------------------------------------------+
| agent.monitor.*                              | monitor.*                                  |
+----------------------------------------------+--------------------------------------------+
| global.nodePort.acceleration                 | loadBalancer.acceleration                  |
+----------------------------------------------+--------------------------------------------+
| global.nodePort.autoProtectPortRange         | nodePort.autoProtectPortRange              |
+----------------------------------------------+--------------------------------------------+
| global.nodePort.bindProtection               | nodePort.bindProtection                    |
+----------------------------------------------+--------------------------------------------+
| global.nodePort.enableHealthCheck            | nodePort.enableHealthCheck                 |
+----------------------------------------------+--------------------------------------------+
| global.nodePort.enabled                      | nodePort.enabled                           |
+----------------------------------------------+--------------------------------------------+
| global.nodePort.mode                         | loadBalancer.mode                          |
+----------------------------------------------+--------------------------------------------+
| global.nodePort.range                        | nodePort.range                             |
+----------------------------------------------+--------------------------------------------+
| global.nodeinit.bootstrapFile                | nodeinit.bootstrapFile                     |
+----------------------------------------------+--------------------------------------------+
| global.nodeinit.enabled                      | nodeinit.enabled                           |
+----------------------------------------------+--------------------------------------------+
| global.pullPolicy                            | nodeinit.image.pullPolicy                  |
+----------------------------------------------+--------------------------------------------+
| nodeinit.image                               | nodeinit.image.repository                  |
+----------------------------------------------+--------------------------------------------+
| global.tag                                   | nodeinit.image.tag                         |
+----------------------------------------------+--------------------------------------------+
| global.endpointGCInterval                    | operator.endpointGCInterval                |
+----------------------------------------------+--------------------------------------------+
| global.identityGCInterval                    | operator.identityGCInterval                |
+----------------------------------------------+--------------------------------------------+
| global.identityHeartbeatTimeout              | operator.identityHeartbeatTimeout          |
+----------------------------------------------+--------------------------------------------+
| global.pullPolicy                            | operator.image.pullPolicy                  |
+----------------------------------------------+--------------------------------------------+
| operator.image                               | operator.image.repository                  |
+----------------------------------------------+--------------------------------------------+
| global.tag                                   | operator.image.tag                         |
+----------------------------------------------+--------------------------------------------+
| global.operatorPrometheus.enabled            | operator.prometheus.enabled                |
+----------------------------------------------+--------------------------------------------+
| global.operatorPrometheus.port               | operator.prometheus.port                   |
+----------------------------------------------+--------------------------------------------+
| global.prometheus.serviceMonitor.enabled     | operator.prometheus.serviceMonitor.enabled |
+----------------------------------------------+--------------------------------------------+
| operator.numReplicas                         | operator.replicas                          |
+----------------------------------------------+--------------------------------------------+
| config.policyAuditMode                       | policyAuditMode                            |
+----------------------------------------------+--------------------------------------------+
| agent.policyEnforcementMode                  | policyEnforcementMode                      |
+----------------------------------------------+--------------------------------------------+
| global.pprof.enabled                         | pprof.enabled                              |
+----------------------------------------------+--------------------------------------------+
| global.prometheus.enabled                    | prometheus.enabled                         |
+----------------------------------------------+--------------------------------------------+
| global.prometheus.port                       | prometheus.port                            |
+----------------------------------------------+--------------------------------------------+
| global.prometheus.serviceMonitor.enabled     | prometheus.serviceMonitor.enabled          |
+----------------------------------------------+--------------------------------------------+
| global.proxy.sidecarImageRegex               | proxy.sidecarImageRegex                    |
+----------------------------------------------+--------------------------------------------+
| global.remoteNodeIdentity                    | remoteNodeIdentity                         |
+----------------------------------------------+--------------------------------------------+
| agent.sleepAfterInit                         | sleepAfterInit                             |
+----------------------------------------------+--------------------------------------------+
| global.sockops.enabled                       | sockops.enabled                            |
+----------------------------------------------+--------------------------------------------+
| global.synchronizeK8sNodes                   | synchronizeK8sNodes                        |
+----------------------------------------------+--------------------------------------------+
| global.tls.enabled                           | tls.enabled                                |
+----------------------------------------------+--------------------------------------------+
| global.tls.secretsBackend                    | tls.secretsBackend                         |
+----------------------------------------------+--------------------------------------------+
| global.tunnel                                | tunnel                                     |
+----------------------------------------------+--------------------------------------------+
| global.wellKnownIdentities.enabled           | wellKnownIdentities.enabled                |
+----------------------------------------------+--------------------------------------------+

Renamed Metrics
~~~~~~~~~~~~~~~

The following metrics have been renamed:

* ``cilium_operator_ipam_ec2_resync`` to ``cilium_operator_ipam_resync``
* ``ipam_cilium_operator_api_duration_seconds`` to ``cilium_operator_ec2_api_duration_seconds``
* ``ipam_cilium_operator_api_rate_limit_duration_seconds`` to ``cilium_operator_ec2_api_rate_limit_duration_seconds``

New Metrics
~~~~~~~~~~~

  * ``cilium_endpoint_regenerations_total`` counts of all endpoint regenerations that have completed, tagged by outcome.
  * ``cilium_k8s_client_api_calls_total`` is number of API calls made to kube-apiserver labeled by host, method and return code.
  * ``cilium_kvstore_quorum_errors_total`` counts the number of kvstore quorum
    loss errors. The label ``error`` indicates the type of error.

Deprecated Metrics/Labels
~~~~~~~~~~~~~~~~~~~~~~~~~

  * ``cilium_endpoint_regenerations`` is deprecated and will be removed in 1.10. Please use ``cilium_endpoint_regenerations_total`` instead.
  * ``cilium_k8s_client_api_calls_counter``is deprecated and will be removed in 1.10. Please use ``cilium_k8s_client_api_calls_total`` instead.
  * ``cilium_identity_count`` is deprecated and will be removed in 1.10. Please use ``cilium_identity`` instead.
  * ``cilium_policy_count`` is deprecated and will be removed in 1.10. Please use ``cilium_policy`` instead.
  * ``cilium_policy_import_errors`` is deprecated and will be removed in 1.10. Please use ``cilium_policy_import_errors_total`` instead.
  * Label ``mapName`` in ``cilium_bpf_map_ops_total`` is deprecated and will be removed in 1.10. Please use label ``map_name`` instead.
  * Label ``eventType`` in ``cilium_nodes_all_events_received_total`` is deprecated and will be removed in 1.10. Please use
    label ``event_type`` instead.
  * Label ``responseCode`` in ``*api_duration_seconds`` is deprecated and will be removed in 1.10. Please use
    label ``response_code`` instead.
  * Label ``subnetId`` in ``cilium_operator_ipam_allocation_ops`` is deprecated and will be removed in 1.10. Please use
    label ``subnet_id`` instead.
  * Label ``subnetId`` in ``cilium_operator_ipam_release_ops`` is deprecated and will be removed in 1.10. Please use
    label ``subnet_id`` instead.
  * Label ``subnetId`` and ``availabilityZone`` in ``cilium_operator_ipam_available_ips_per_subnet`` are deprecated and will be removed in 1.10. Please use
    label ``subnet_id`` and ``availability_zone`` instead.
  * Label ``scope`` in ``cilium_endpoint_regeneration_time_stats_seconds`` had its ``buildDuration`` value renamed to ``total``.
  * Label ``scope`` in ``cilium_policy_regeneration_time_stats_seconds`` had its ``buildDuration`` value renamed to ``total``.

Deprecated options
~~~~~~~~~~~~~~~~~~

* ``k8s-watcher-queue-size``: This option does not have any effect since 1.8
  and is planned to be removed in 1.10.

Removed options
~~~~~~~~~~~~~~~

* ``disable-ipv4``, ``ipv4-cluster-cidr-mask-size``, ``keep-bpf-templates``,
  ``disable-k8s-services``: These options were deprecated in Cilium 1.8 and
  are now removed.
* The ``prometheus-serve-addr-deprecated`` option is now removed. Please use
  ``prometheus-serve-addr`` instead.
* The ``hostscope-legacy`` option value for ``ipam`` is now removed. The ``ipam``
  option now defaults to ``cluster-pool``.
* ``--tofqdns-enable-poller``, ``--tofqdns-enable-poller-events``: These option
  were deprecated in Cilium 1.8 and are now removed

Removed cilium-operator options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* The options ``cnp-node-status-gc`` and ``ccnp-node-status-gc`` are now
  removed. Please use ``cnp-node-status-gc-interval=0`` instead.

* The ``cilium-endpoint-gc`` option is now removed. Please use
  ``cilium-endpoint-gc-interval=0`` instead.

* The ``eni-parallel-workers`` option is now removed. Please use
  ``parallel-alloc-workers`` instead.

* The ``aws-client-burst`` option is now removed. Please use
  ``limit-ipam-api-burst`` instead.

* The ``aws-client-qps`` option is now removed. Please use
  ``limit-ipam-api-qps`` instead.

* The ``api-server-port`` option is now removed. Please use
  ``operator-api-serve-addr`` instead.

* The ``metrics-address`` option is now removed. Please use
  ``operator-prometheus-serve-addr`` instead.

* The ``hostscope-legacy`` option value for ``ipam`` is now removed. The ``ipam``
  option now defaults to ``cluster-pool``.

.. _1.8_upgrade_notes:

1.8 Upgrade Notes
-----------------

.. _1.8_required_changes:

IMPORTANT: Changes required before upgrading to 1.8.0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::

   Do not upgrade to 1.8.0 before reading the following section and completing
   the required steps.

* The ``cilium-agent`` container ``liveness`` and ``readiness`` probes have been
  replaced with a ``httpGet`` instead of an ``exec`` probe. Unfortunately,
  upgrading using ``kubectl apply`` does not work since the merge strategy done
  by Kubernetes does not remove the old probe when replacing with a new one.
  This causes ``kubectl apply`` command to return an error such as:

  ::

    The DaemonSet "cilium" is invalid:
    * spec.template.spec.containers[0].livenessProbe.httpGet: Forbidden: may not specify more than 1 handler type
    * spec.template.spec.containers[0].readinessProbe.httpGet: Forbidden: may not specify more than 1 handler type

  Existing users must either choose to keep the ``exec`` probe in the
  `DaemonSet` specification to safely upgrade or re-create the Cilium `DaemonSet`
  without the deprecated probe. It is advisable to keep the probe when doing
  an upgrade from ``v1.7.x`` to ``v1.8.x`` in the event of having to do a
  downgrade. The removal of this probe should be done after a successful
  upgrade.

  The Helm option ``agent.keepDeprecatedProbes=true`` will keep the
  ``exec`` probe in the new `DaemonSet`. Add this option along with any
  other options you would otherwise specify to Helm:

.. tabs::
  .. group-tab:: kubectl

    .. code-block:: shell-session

      helm template cilium \
      --namespace=kube-system \
      ...
      --set agent.keepDeprecatedProbes=true \
      ...
      > cilium.yaml
      kubectl apply -f cilium.yaml

  .. group-tab:: Helm

    .. code-block:: shell-session

      helm upgrade cilium --namespace=kube-system \
      --set agent.keepDeprecatedProbes=true

* **Important:** The masquerading behavior has changed, depending on how you
  have configured masquerading you need to take action to avoid potential
  NetworkPolicy related drops:

  Running the default configuration (``--tunnel=vxlan`` or ``--tunnel=geneve``)
    No action required. The behavior remains the same as before. All traffic
    leaving the node that is not encapsulated is automatically masqueraded. You
    may use ``--native-routing-cidr`` to further restrict traffic subject to
    masquerading.

  Already using ``--native-routing-cidr`` and/or ``--egress-masquerade-interfaces``
    No action required. Use of ``--native-routing-cidr`` is the preferred way of
    configuring masquerading.

  Running in AWS ENI mode (``--ipam=eni``)
    No action required. The value for ``--native-routing-cidr`` is
    automatically derived from the AWS API and set to the CIDR of the VPC. You
    may overwrite the value if needed.

  Running with ``--masquerade=false`` (all chaining configurations)
    No action required.

  Running in direct-routing configuration (``--tunnel=disabled``)
    The behavior has changed: Previously, the destination address range
    excluded from masquerading was defined by the options ``--ipv4-range`` and
    ``--ipv4-cluster-cidr-mask-size``. When unspecified, this was set to the
    value ``10.0.0.0/8``. You **must** set the ``--native-routing-cidr`` option
    and set it to the CIDR for which masquerading should be omitted. This is
    typically the PodCIDR range of the cluster but can also be set to the IP
    range of the network the node is running on to avoid masquerading for
    directly reachable destinations outside of the cluster.

    **Important:** If not set, all traffic leaving the node will be
    masqueraded. This will result in all traffic within the cluster to be
    considered coming from identity ``remote-node`` instead of the true pod
    identity. If NetworkPolicies are in place, then this will typically result
    in traffic being dropped due to policy.

  For more information, see section :ref:`concepts_masquerading`.

* When all nodes in a cluster are enforcing a particular ``CiliumNetworkPolicy``.
  For large clusters running CRD mode, this visibility is costly as it requires
  all nodes to participate. In order to ensure scalability, ``CiliumNetworkPolicy``
  status visibility has been disabled for all new deployments. If you want to
  enable it, set the ConfigMap option ``disable-cnp-status-updates`` to false or
  set the Helm variable ``--set config.enableCnpStatusUpdates=true``.

* Prior to 1.8 release, Cilium's eBPF-based kube-proxy replacement was not able
  to handle Kubernetes HostPort feature and therefore CNI chaining with the
  ``portmap`` plugin (``global.cni.chainingMode=portmap``) was necessary while
  turning off the kube-proxy replacement (``global.kubeProxyReplacement=disabled``).
  Starting from 1.8, CNI chaining is no longer necessary, meaning Cilium can be
  used natively to handle HostPort when running with Cilium's kube-proxy replacement.
  That is, for ``global.kubeProxyReplacement=probe`` and ``global.kubeProxyReplacement=strict``
  handling of HostPort is enabled by default. HostPort has the same system requirements
  as eBPF-based NodePort, so for ``probe`` the former gets enabled if also NodePort
  could be enabled. For more information, see section :ref:`kubeproxyfree_hostport`.

Upgrading from >=1.7.0 to 1.8.y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Since Cilium 1.5, the TCP connection tracking table size parameter
  ``bpf-ct-global-tcp-max`` in the daemon was set to the default value
  ``1000000`` to retain backwards compatibility with previous versions. In
  Cilium 1.8 the default value is set to 512K by default in order to reduce the
  agent memory consumption.

  If Cilium was deployed using Helm, the new default value of 512K was already
  effective in Cilium 1.6 or later, unless it was manually configured to a
  different value.

  If the table size was configured to a value different from 512K in the
  previous installation, ongoing connections will be disrupted during the
  upgrade. To avoid connection breakage, ``bpf-ct-global-tcp-max`` needs to be
  manually adjusted.

  To check whether any action is required the following command can be used to
  check the currently configured maximum number of TCP conntrack entries:

  .. code-block:: shell-session

     sudo grep -R CT_MAP_SIZE_TCP /var/run/cilium/state/templates/

  If the maximum number is 524288, no action is required. If the number is
  different, ``bpf-ct-global-tcp-max`` needs to be adjusted in the `ConfigMap`
  to the value shown by the command above (100000 in the example below):

.. tabs::
  .. group-tab:: kubectl

    .. code-block:: shell-session

      helm template cilium \\
      --namespace=kube-system \\
      ...
      --set global.bpf.ctTcpMax=100000
      ...
      > cilium.yaml
      kubectl apply -f cilium.yaml

  .. group-tab:: Helm

    .. code-block:: shell-session

      helm upgrade cilium --namespace=kube-system \\
      --set global.bpf.ctTcpMax=100000

* The default value for the NAT table size parameter ``bpf-nat-global-max`` in
  the daemon is derived from the default value of the conntrack table size
  parameter ``bpf-ct-global-tcp-max``. Since the latter was changed (see
  above), the default NAT table size decreased from ~820K to 512K.

  The NAT table is only used if either eBPF NodePort (``enable-node-port``
  parameter) or masquerading (``masquerade`` parameter) are enabled. No action
  is required if neither of the parameters is enabled.

  If either of the parameters is enabled, ongoing connections will be disrupted
  during the upgrade. In order to avoid connection breakage,
  ``bpf-nat-global-max`` needs to be manually adjusted.

  To check whether any adjustment is required the following command can be used
  to check the currently configured maximum number of NAT table entries:

  .. code-block:: shell-session

     sudo grep -R SNAT_MAPPING_IPV[46]_SIZE /var/run/cilium/state/globals/

  If the command does not return any value or if the returned maximum number is
  524288, no action is required. If the number is different,
  ``bpf-nat-global-max`` needs to be adjusted in the `ConfigMap` to the value
  shown by the command above (841429 in the example below):

.. tabs::
  .. group-tab:: kubectl

    .. code-block:: shell-session

      helm template cilium \\
      --namespace=kube-system \\
      ...
      --set global.bpf.natMax=841429
      ...
      > cilium.yaml
      kubectl apply -f cilium.yaml

  .. group-tab:: Helm

    .. code-block:: shell-session

      helm upgrade cilium --namespace=kube-system \\
      --set global.bpf.natMax=841429

* Setting debug mode with ``debug: "true"`` no longer enables datapath debug
  messages which could have been read with ``cilium monitor -v``. To enable
  them, add ``"datapath"`` to the ``debug-verbose`` option.

New ConfigMap Options
~~~~~~~~~~~~~~~~~~~~~

  * ``bpf-map-dynamic-size-ratio`` has been added to allow dynamic sizing of the
    largest eBPF maps: ``cilium_ct_{4,6}_global``, ``cilium_ct_{4,6}_any``,
    ``cilium_nodeport_neigh{4,6}``, ``cilium_snat_v{4,6}_external`` and
    ``cilium_lb{4,6}_reverse_sk``.  This option allows to specify a ratio
    (0.0-1.0) of total system memory to use for these maps. On new
    installations, this ratio is set to 0.0025 by default, leading to 0.25% of
    the total system memory to be allocated for these maps. On a node with 4 GiB
    of total system memory this ratio corresponds approximately to the defaults
    used by ``kube-proxy``, see :ref:`bpf_map_limitations` for details. A value
    of 0.0 will disable sizing of the eBPF maps based on system memory. Any eBPF
    map sizes configured manually using the ``bpf-ct-global-tcp-max``,
    ``bpf-ct-global-any-max``, ``bpf-nat-global-max`` or
    ``bpf-neigh-global-max`` options will take precedence over the dynamically
    determined value.

    On upgrades of existing installations, this option is disabled by default,
    i.e. it is set to 0.0. Users wanting to use this feature need to enable it
    explicitly in their `ConfigMap`, see section :ref:`upgrade_configmap`.

  * ``enable-health-check-nodeport`` has been added to allow to configure
    NodePort server health check when kube-proxy is disabled.

Deprecated options
~~~~~~~~~~~~~~~~~~

* ``keep-bpf-templates``: This option no longer has any effect due to the eBPF
  assets not being compiled into the cilium-agent binary anymore. The option is
  deprecated and will be removed in Cilium 1.9.
* ``--disable-k8s-services`` option from cilium-agent has been deprecated
  and will be removed in Cilium 1.9.
* ``--disable-ipv4`` legacy option from cilium-agent which was already hidden
  has now been deprecated and will be removed in Cilium 1.9.
* ``--tofqdns-enable-poller``: This option has been deprecated and will be
  removed in Cilium 1.9
* ``--tofqdns-enable-poller-events``: This option has been deprecated and will
  be removed in Cilium 1.9

New Metrics
~~~~~~~~~~~

The following metrics have been added:

* ``bpf_maps_virtual_memory_max_bytes``: Max memory used by eBPF maps installed
  in the system
* ``bpf_progs_virtual_memory_max_bytes``: Max memory used by eBPF programs
  installed in the system

Both ``bpf_maps_virtual_memory_max_bytes`` and ``bpf_progs_virtual_memory_max_bytes``
are currently reporting the system-wide memory usage of eBPF that is directly
and not directly managed by Cilium. This might change in the future and only
report the eBPF memory usage directly managed by Cilium.

Renamed Metrics
~~~~~~~~~~~~~~~

The following metrics have been renamed:

* ``cilium_operator_eni_ips`` to ``cilium_operator_ipam_ips``
* ``cilium_operator_eni_allocation_ops`` to ``cilium_operator_ipam_allocation_ops``
* ``cilium_operator_eni_interface_creation_ops`` to ``cilium_operator_ipam_interface_creation_ops``
* ``cilium_operator_eni_available`` to ``cilium_operator_ipam_available``
* ``cilium_operator_eni_nodes_at_capacity`` to ``cilium_operator_ipam_nodes_at_capacity``
* ``cilium_operator_eni_resync_total`` to ``cilium_operator_ipam_resync_total``
* ``cilium_operator_eni_aws_api_duration_seconds`` to ``cilium_operator_ipam_api_duration_seconds``
* ``cilium_operator_eni_ec2_rate_limit_duration_seconds`` to ``cilium_operator_ipam_api_rate_limit_duration_seconds``

Deprecated cilium-operator options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* ``metrics-address``: This option is being deprecated and a new flag is
  introduced to replace its usage. The new option is ``operator-prometheus-serve-addr``.
  This old option will be removed in Cilium 1.9

* ``ccnp-node-status-gc``: This option is being deprecated. Disabling CCNP node
  status GC can be done with ``cnp-node-status-gc-interval=0``. (Note that this
  is not a typo, it is meant to be ``cnp-node-status-gc-interval``).
  This old option will be removed in Cilium 1.9

* ``cnp-node-status-gc``: This option is being deprecated. Disabling CNP node
  status GC can be done with ``cnp-node-status-gc-interval=0``.
  This old option will be removed in Cilium 1.9

* ``cilium-endpoint-gc``: This option is being deprecated. Disabling cilium
  endpoint GC can be done with ``cilium-endpoint-gc-interval=0``.
  This old option will be removed in Cilium 1.9

* ``api-server-port``: This option is being deprecated. The API Server address
  and port can be enabled with ``operator-api-serve-addr=127.0.0.1:9234``
  or ``operator-api-serve-addr=[::1]:9234`` for IPv6-only clusters.
  This old option will be removed in Cilium 1.9

* ``eni-parallel-workers``: This option in the Operator has been renamed to
  ``parallel-alloc-workers``. The obsolete option name ``eni-parallel-workers``
  has been deprecated and will be removed in v1.9.

* ``aws-client-burst``: This option in the Operator has been renamed to
  ``limit-ipam-api-burst``. The obsolete option name ``aws-client-burst`` has been
  deprecated and will be removed in v1.9.

* ``aws-client-qps``: This option in the Operator has been renamed to
  ``limit-ipam-api-qps``. The obsolete option name ``aws-client-qps`` has been
  deprecated and will be removed in v1.9.

Removed options
~~~~~~~~~~~~~~~

* ``access-log``: L7 access logs have been available via Hubble since Cilium
  1.6. The ``access-log`` option to log to a file has been removed.
* ``enable-legacy-services``: This option was deprecated in Cilium 1.6 and is
  now removed.
* The options ``container-runtime``, ``container-runtime-endpoint`` and
  ``flannel-manage-existing-containers`` were deprecated in Cilium 1.7 and are now removed.
* The ``conntrack-garbage-collector-interval`` option deprecated in Cilium 1.6
  is now removed. Please use ``conntrack-gc-interval`` instead.

Removed Helm options
~~~~~~~~~~~~~~~~~~~~
* ``operator.synchronizeK8sNodes``: was removed and replaced with ``config.synchronizeK8sNodes``

Removed resource fields
~~~~~~~~~~~~~~~~~~~~~~~

* The fields ``CiliumEndpoint.Status.Status``,
  ``CiliumEndpoint.Status.Spec``, and ``EndpointIdentity.LabelsSHA256``,
  deprecated in 1.4, have been removed.

Advanced
========

Upgrade Impact
--------------

Upgrades are designed to have minimal impact on your running deployment.
Networking connectivity, policy enforcement and load balancing will remain
functional in general. The following is a list of operations that will not be
available during the upgrade:

* API aware policy rules are enforced in user space proxies and are currently
  running as part of the Cilium pod unless Cilium is configured to run in Istio
  mode. Upgrading Cilium will cause the proxy to restart which will result in
  a connectivity outage and connection to be reset.

* Existing policy will remain effective but implementation of new policy rules
  will be postponed to after the upgrade has been completed on a particular
  node.

* Monitoring components such as ``cilium monitor`` will experience a brief
  outage while the Cilium pod is restarting. Events are queued up and read
  after the upgrade. If the number of events exceeds the event buffer size,
  events will be lost.


.. _upgrade_configmap:

Rebasing a ConfigMap
--------------------

This section describes the procedure to rebase an existing `ConfigMap` to the
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
            - https://192.168.33.11:2379
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


In the `ConfigMap` above, we can verify that Cilium is using ``debug`` with
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

Add the new options manually to your old `ConfigMap`, and make the necessary
changes.

In this example, the ``debug`` option is meant to be kept with ``true``, the
``etcd-config`` is kept unchanged, and ``monitor-aggregation`` is a new
option, but after reading the :ref:`version_notes` the value was kept unchanged
from the default value.

After making the necessary changes, the old `ConfigMap` was migrated with the
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
            - https://192.168.33.11:2379
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
the `ConfigMap` in the ``kube-system`` namespace of your cluster.

.. code-block:: shell-session

        $ kubectl apply -n kube-system -f ./cilium-cm-old.yaml

As the `ConfigMap` is successfully upgraded we can start upgrading Cilium
``DaemonSet`` and ``RBAC`` which will pick up the latest configuration from the
`ConfigMap`.


.. _cidr_limitations:

Restrictions on unique prefix lengths for CIDR policy rules
-----------------------------------------------------------

The Linux kernel applies limitations on the complexity of eBPF code that is
loaded into the kernel so that the code may be verified as safe to execute on
packets. Over time, Linux releases become more intelligent about the
verification of programs which allows more complex programs to be loaded.
However, the complexity limitations affect some features in Cilium depending
on the kernel version that is used with Cilium.

One such limitation affects Cilium's configuration of CIDR policies. On Linux
kernels 4.10 and earlier, this manifests as a restriction on the number of
unique prefix lengths supported in CIDR policy rules.

Unique prefix lengths are counted by looking at the prefix portion of CIDR
rules and considering which prefix lengths are unique. For example, in the
following policy example, the ``toCIDR`` section specifies a ``/32``, and the
``toCIDRSet`` section specifies a ``/8`` with a ``/12`` removed from it. In
addition, three prefix lengths are always counted: the host prefix length for
the protocol (IPv4: ``/32``, IPv6: ``/128``), the default prefix length
(``/0``), and the cluster prefix length (default IPv4: ``/8``, IPv6: ``/64``).
All in all, the following example counts as seven unique prefix lengths in IPv4:

* ``/32`` (from ``toCIDR``, also from host prefix)
* ``/12`` (from ``toCIDRSet``)
* ``/11`` (from ``toCIDRSet``)
* ``/10`` (from ``toCIDRSet``)
* ``/9`` (from ``toCIDRSet``)
* ``/8`` (from cluster prefix)
* ``/0`` (from default prefix)

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l3/cidr/cidr.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l3/cidr/cidr.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l3/cidr/cidr.json

Affected versions
~~~~~~~~~~~~~~~~~

* Any version of Cilium running on Linux 4.10 or earlier

When a CIDR policy with too many unique prefix lengths is imported, Cilium will
reject the policy with a message like the following:

.. code-block:: shell-session

  $ cilium policy import too_many_cidrs.json
  Error: Cannot import policy: [PUT /policy][500] putPolicyFailure  Adding
  specified prefixes would result in too many prefix lengths (current: 3,
  result: 32, max: 18)

The supported count of unique prefix lengths may differ between Cilium minor
releases, for example Cilium 1.1 supported 20 unique prefix lengths on Linux
4.10 or older, while Cilium 1.2 only supported 18 (for IPv4) or 4 (for IPv6).

Mitigation
~~~~~~~~~~

Users may construct CIDR policies that use fewer unique prefix lengths. This
can be achieved by composing or decomposing adjacent prefixes.

Solution
~~~~~~~~

Upgrade the host Linux version to 4.11 or later. This step is beyond the scope
of the Cilium guide.


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
      --set global.etcd.enabled=true \
      --set global.etcd.ssl=true \
      > cilium-preflight.yaml
    kubectl create -f cilium-preflight.yaml


Example migration
~~~~~~~~~~~~~~~~~

.. code-block:: shell-session

      $ kubectl exec -n kube-system cilium-preflight-1234 -- cilium preflight migrate-identity
      INFO[0000] Setting up kvstore client
      INFO[0000] Connecting to etcd server...                  config=/var/lib/cilium/etcd-config.yml endpoints="[https://192.168.33.11:2379]" subsys=kvstore
      INFO[0000] Setting up kubernetes client
      INFO[0000] Establishing connection to apiserver          host="https://192.168.33.11:6443" subsys=k8s
      INFO[0000] Connected to apiserver                        subsys=k8s
      INFO[0000] Got lease ID 29c66c67db8870c8                 subsys=kvstore
      INFO[0000] Got lock lease ID 29c66c67db8870ca            subsys=kvstore
      INFO[0000] Successfully verified version of etcd endpoint  config=/var/lib/cilium/etcd-config.yml endpoints="[https://192.168.33.11:2379]" etcdEndpoint="https://192.168.33.11:2379" subsys=kvstore version=3.3.13
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

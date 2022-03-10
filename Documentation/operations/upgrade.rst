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
questions, feel free to ping us on the :term:`Slack channel`.

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
1.x to 1.y, it is recommended to upgrade to the latest patch release for a
Cilium release series first. The latest patch releases for each supported
version of Cilium are `here <https://github.com/cilium/cilium#stable-releases>`_.
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

.. include:: ../gettingstarted/k8s-install-download-release.rst

To minimize datapath disruption during the upgrade, the
``upgradeCompatibility`` option should be set to the initial Cilium
version which was installed in this cluster. Valid options are:

* ``1.7`` if the initial install was Cilium 1.7.x or earlier.
* ``1.8`` if the initial install was Cilium 1.8.x.
* ``1.9`` if the initial install was Cilium 1.9.x.
* ``1.10`` if the initial install was Cilium 1.10.x.

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
      kubeProxyReplacement: "strict"

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

This section documents the specific steps required for upgrading from one
version of Cilium to another version of Cilium. There are particular version
transitions which are suggested by the Cilium developers to avoid known issues
during upgrade, then subsequently there are sections for specific upgrade
transitions, ordered by version.

The table below lists suggested upgrade transitions, from a specified current
version running in a cluster to a specified target version. If a specific
combination is not listed in the table below, then it may not be safe. In that
case, consider performing incremental upgrades between versions (e.g. upgrade
from ``1.9.x`` to ``1.10.y`` first, and to ``1.11.z`` only afterwards).

+-----------------------+-----------------------+-------------------------+---------------------------+
| Current version       | Target version        | L3/L4 impact            | L7 impact                 |
+=======================+=======================+=========================+===========================+
| ``1.10.x``            | ``1.11.y``            | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.9.x``             | ``1.10.y``            | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.8.x``             | ``1.9.y``             | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+-------------------------+---------------------------+

Annotations:

#. **Clients must reconnect**: Any traffic flowing via a proxy (for example,
   because an L7 policy is in place) will be disrupted during upgrade.
   Endpoints communicating via the proxy must reconnect to re-establish
   connections.

.. _current_release_required_changes:

.. _1.12_upgrade_notes:

1.12 Upgrade Notes
------------------

* The Cilium agent does not support the legacy ``nat46-range`` option as well
  as the per-endpoint ``NAT46`` configuration anymore. Both are replaced in
  favor of NAT46/64 handling for services.
* The kube-proxy replacement in the tunneling mode (i.e., ``vxlan`` or
  ``geneve``) will set the ``reserved:world`` security identity for all service
  requests coming from outside the cluster. Previously, when a selected service
  endpoint was on a different node, the security identity was set to the
  ``reserved:remote-node``. The change might impact those who have a network policy
  allowing access to the service from inside the cluster, and the policy was used
  to allow access from outside.

New Options
~~~~~~~~~~~

* ``ipv6-native-routing-cidr``: This option specifies the IPv6 CIDR for native
  routing. It must be set whenever running in direct routing mode with IPv6
  masquerading enabled.
* ``instance-tags-filter``: This option specifies a list of tags used to search
  for EC2 instances (and existing ENIs). EC2 Instances tags is in the form of k1=v1,k2=v2
  (multiple k/v pairs can also be passed by repeating the CLI flag")
  Use ``instanceTagsFilter`` in Helm chart.
* ``nodes-gc-interval``: This option was marked as deprecated and has no effect
  in 1.11. Cilium Node Garbage collector is added back in 1.12 (but for k8s GC instead
  of kvstore), so this flag is moved out of deprecated list.

Removed Options
~~~~~~~~~~~~~~~

* The endpoint config option ``Conntrack`` was removed. The option was used
  to disable the stateful connection tracking for the endpoint. However, many
  Cilium features depend on the tracking. Therefore the option to disable the
  connection tracking was removed. In addition, we deprecated the
  ``disable-conntrack`` option and made it non-operational. It will be removed
  in version 1.13.
* The ``host-reachable-services-protos`` option (``.hostServices.protocols`` in
  Helm) was deprecated, and it will be removed in version 1.13.
* The ``native-routing-cidr`` option deprecated in 1.11 in favor of
  ``ipv4-native-routing-cidr`` has been removed.
* The ``prefilter-device`` and ``prefilter-mode`` options deprecated in 1.11 in
  favor of ``enable-xdp-prefilter`` and ``bpf-lb-acceleration`` have been removed.

Deprecated Options
~~~~~~~~~~~~~~~~~~

* The ``CiliumEgressNATPolicy`` CRD has been deprecated, and will be removed in
  version 1.13. It is superseded by the ``CiliumEgressGatewayPolicy`` CRD, which
  allows for better selection of the Egress Node, Egress Interface and Masquerade IP.

Helm Options
~~~~~~~~~~~~

* ``bandwidthManager`` has been deprecated in favor of ``bandwidthManager.enabled``,
  and will be removed in 1.13.
* ``bpf.hostRouting`` has been deprecated in favor of ``bpf.hostLegacyRouting``, and
  will be removed in 1.13.
* ``hubble.tls.ca.cert`` has been deprecated in favor of ``tls.ca.cert``, and
  will be removed in 1.13.
* ``hubble.tls.ca.key`` has been deprecated in favor of ``tls.ca.key``, and will be
  removed in 1.13.
* ``hubble.ui.securityContext.enabled`` has been deprecated in favor of
  ``hubble.ui.securityContext``, and will be removed in 1.13.
* ``clustermesh.apiserver.tls.ca.cert`` has been deprecated in favor of ``tls.ca.key``,
  and will be removed in 1.13.
* ``clustermesh.apiserver.tls.ca.key`` has been deprecated in favor of ``tls.ca.key``,
  and will be removed in 1.13.
* ``operator.unmanagedPodWatcher.restart`` has been introduced to govern
  whether the cilium-operator will attempt to restart pods that are not
  managed by Cilium. To retain consistency with earlier releases, this setting
  is enabled by default.
* ``tls.enabled`` has been removed as this attribute is not used at all.
* Only one CA will be generated with either the helm or CronJob auto method, there will
  be a short disruption while the new CA is propagated to all nodes.

.. _1.11_upgrade_notes:

1.11 Upgrade Notes
------------------

* The Cilium agent will now fail instead of falling back to auto-detection
  when device wildcard expansion (``--devices=eth+``) yields no devices.
* Device auto-detection now discovers devices through the routing table and
  only considers devices that have a global unicast route in some routing table.
* The XDP-based prefilter is enabled for all devices specified by ``--devices``
  if ``--prefilter-device`` is set.
* New flags were added to enable installation where alternative VXLAN/Geneve and
  health ports need to be used (``--tunnel-port`` and ``--cluster-health-port``).
  Default values of these flags haven't changed, however if ``--tunnel-port`` gets
  set to non-default values on upgrade, there will datapath downtime between nodes.
  If ``--tunnel-port`` needs to change, it's recommended to perform the upgrade
  first, and change the port afterwards, in order to separate agent upgrade from
  configuration update. Changing ``--cluster-health-port`` will not affect datapath,
  however it's recommended to still handle configuration change separately from
  agent upgrade. Changing both ports simultaneously shouldn't cause any issues.
* When Egress Gateway is enabled, upgrading to 1.11 will cause a brief
  interruption of the connectivity between the client pods and the egress
  gateway nodes. Once the connectivity is restored, clients will need to
  reconnect.

Removed Metrics/Labels
~~~~~~~~~~~~~~~~~~~~~~

* ``cilium_operator_identity_gc_entries_total`` is removed. Please use ``cilium_operator_identity_gc_entries`` instead.
* ``cilium_operator_identity_gc_runs_total`` is removed. Please use ``cilium_operator_identity_gc_runs`` instead.

Removed Options
~~~~~~~~~~~~~~~

* ``bpf-compile-debug``: This option does not have any effect since 1.10
  and is now removed.
* ``k8s-force-json-patch``: This option does not have any effect for
  environments running Kubernetes >= 1.13, is deprecated since 1.10, and
  now removed.
* ``masquerade``: This option has been deprecated in 1.10 and replaced by
  ``enable-ipv4-masquerade``.
* ``skip-crd-creation``: This option does not have any effect since 1.10
  and is now removed.
* ``hubble-flow-buffer-size``: This option was deprecated in 1.10 in favor
  of ``hubble-event-buffer-capacity``. It is now removed.
* The ``Capabilities`` Helm value has been removed. When using ``helm template``
  to generate the Kubernetes manifest for a specific Kubernetes version,
  please use the ``--kube-version`` flag (introduced in Helm 3.6.0) instead.
* The deprecated ``hubble-ca-cert`` ConfigMap has been removed. Use
  ``hubble-ca-secret`` secret instead.
* The ``azure-cloud-name`` option for ``cilium-operator-azure`` was deprecated
  in 1.10 and is now removed.

Deprecated Options
~~~~~~~~~~~~~~~~~~

* ``native-routing-cidr``: This option has been deprecated in favor of
  ``ipv4-native-routing-cidr`` and will be removed in 1.12.
* ``prefilter-device`` and ``prefilter-mode``: These options have been
  deprecated in favor of ``enable-xdp-prefilter`` and ``bpf-lb-acceleration``,
  and will be removed in 1.12. To select the prefilter devices use ``devices``.
* The NodePort related ``bpf-lb-bypass-fib-lookup`` option to enable a FIB
  lookup bypass optimization for NodePort's reverse NAT handling has been
  deprecated as the Linux kernel's FIB table is now always consulted. Thus,
  explicitly setting the option has no effect. It is scheduled for removal
  in 1.12.
* IPVLAN support has been deprecated due to lack of feature support and lack
  of community interest. `Recent improvements Virtual Ethernet device performance
  <https://cilium.io/blog/2020/11/10/cilium-19#veth>`_ have granted many of the
  benefits of IPVLAN to the standard veth mode.
* Support for Consul as a kvstore backend has been deprecated due to a lack
  of community interest. It is planned for removal in 1.12.
* The in-pod Cilium CLI command ``cilium policy trace`` has been deprecated
  in favor of approaches using the `Network Policy Editor <https://app.networkpolicy.io>`_
  or guide for `policy_verdicts`.
* Cilium no longer recognizes label sources from Mesos.

New Options
~~~~~~~~~~~

* ``kvstore-max-consecutive-quorum-errors``: This option configures the max
  acceptable kvstore consecutive quorum errors before the agent assumes
  permanent failure.

Renamed Options
~~~~~~~~~~~~~~~

The following option has been renamed:

* ``enable-egress-gateway`` to ``enable-ipv4-egress-gateway``.

Deprecated Options in Cilium Operator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
* ``nodes-gc-interval``: This option will be removed in 1.12. Its value does not
  have any effect in 1.11.

Helm Options
~~~~~~~~~~~~

* ``hostFirewall`` was renamed to ``hostFirewall.enabled``.
* ``ipam.operator.clusterPoolIPv4PodCIDR`` was deprecated in favor of ``ipam.operator.clusterPoolIPv4PodCIDRList``
* ``ipam.operator.clusterPoolIPv6PodCIDR`` was deprecated in favor of ``ipam.operator.clusterPoolIPv6PodCIDRList``
* ``nativeRoutingCIDR``: was deprecated in favor of ``ipv4NativeRoutingCIDR``

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

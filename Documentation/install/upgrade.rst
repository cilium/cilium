.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _admin_upgrade:

*************
Upgrade Guide
*************

.. _upgrade_general:

This upgrade guide is intended for Cilium 1.4 or later running on Kubernetes.
It is assuming that Cilium has been deployed using standard procedures as
described in the :ref:`k8s_concepts_deployment`. If you have installed Cilium
using the guide :ref:`ds_deploy`, then this is automatically the case. If you 
are looking for instructions for upgrading from a version of Cilium prior to 
1.4, then please consult the documentation from that release.

.. _pre_flight:

Running a pre-flight DaemonSet
==============================


When rolling out an upgrade with Kubernetes, Kubernetes will first terminate the
pod followed by pulling the new image version and then finally spin up the new
image. In order to reduce the downtime of the agent, the new image version can
be pre-pulled. It also verifies that the new image version can be pulled and
avoids ErrImagePull errors during the rollout.

.. tabs::
  .. group-tab:: K8s 1.10

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-pre-flight.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-pre-flight.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-pre-flight.yaml

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-pre-flight.yaml

  .. group-tab:: K8s 1.14

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.14/cilium-pre-flight.yaml

  .. group-tab:: K8s 1.15

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.15/cilium-pre-flight.yaml


After running the cilium-pre-flight.yaml, make sure the number of READY pods
is the same number of Cilium pods running.

.. code-block:: shell-session

    kubectl get daemonset -n kube-system | grep cilium
    NAME                      DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR   AGE
    cilium                    2         2         2       2            2           <none>          1h20m
    cilium-pre-flight-check   2         2         2       2            2           <none>          7m15s

Once the number of READY pods are the same, you can delete cilium-pre-flight-check
`DaemonSet` and proceed with the upgrade.

.. code-block:: shell-session

      kubectl -n kube-system delete ds cilium-pre-flight-check

.. _upgrade_micro:

Upgrading Micro Versions
========================

Micro versions within a particular minor version, e.g. 1.2.x -> 1.2.y, are
always 100% compatible for both up- and downgrades. Upgrading or downgrading is
as simple as changing the image tag version in the `DaemonSet` file:

.. code-block:: shell-session

    kubectl -n kube-system set image daemonset/cilium cilium-agent=docker.io/cilium/cilium:vX.Y.Z
    kubectl -n kube-system rollout status daemonset/cilium

Kubernetes will automatically restart all Cilium according to the
``UpgradeStrategy`` specified in the `DaemonSet`.

.. note::

    Direct version upgrade between minor versions is not recommended as RBAC
    and DaemonSet definitions are subject to change between minor versions.
    See :ref:`upgrade_minor` for instructions on how to up or downgrade between
    different minor versions.

.. _upgrade_minor:

Upgrading Minor Versions
========================

Step 1: Upgrade to latest micro version (Recommended)
-----------------------------------------------------

When upgrading from one minor release to another minor release, for example 1.x
to 1.y, it is recommended to first upgrade to the latest micro release
as documented in (:ref:`upgrade_micro`). This ensures that downgrading by rolling back
on a failed minor release upgrade is always possible and seamless.

Step 2: Upgrade the ConfigMap (Optional)
----------------------------------------

The configuration of Cilium is stored in a `ConfigMap` called
``cilium-config``.  The format is compatible between minor releases so
configuration parameters are automatically preserved across upgrades.  However,
new minor releases may introduce new functionality that require opt-in via the
`ConfigMap`. Refer to the :ref:`upgrade_version_specifics` for a list of new
configuration options for each minor version.

Refer to the section :ref:`upgrade_configmap` for instructions on how to
upgrade a `ConfigMap` to the latest template while preserving your
configuration parameters.

Step 3: Apply new RBAC and DaemonSet definitions
------------------------------------------------

As minor versions typically introduce new functionality which require changes
to the `DaemonSet` and `RBAC` definitions, the YAML definitions have to be
upgraded. The following links refer to version specific DaemonSet files which
automatically

Both files are dedicated to "\ |SCM_BRANCH|" for each Kubernetes version.

.. tabs::
  .. group-tab:: K8s 1.10

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-rbac.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-ds.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-operator-sa.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-operator.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-rbac.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-ds.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-operator-sa.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-operator.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-rbac.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-ds.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-operator-sa.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-operator.yaml

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-rbac.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-ds.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-operator-sa.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-operator.yaml

  .. group-tab:: K8s 1.14

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.14/cilium-rbac.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.14/cilium-ds.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.14/cilium-operator-sa.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.14/cilium-operator.yaml

  .. group-tab:: K8s 1.15

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.15/cilium-rbac.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.15/cilium-ds.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.15/cilium-operator-sa.yaml
      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.15/cilium-operator.yaml


Below we will show examples of how Cilium should be upgraded using Kubernetes
rolling upgrade functionality in order to preserve any existing Cilium
configuration changes (e.g., etc configuration) and minimize network
disruptions for running workloads. These instructions upgrade Cilium to version
"\ |SCM_BRANCH|" by updating the ``ConfigMap``, ``RBAC`` rules and
``DaemonSet`` files separately. Rather than installing all configuration in one
``cilium.yaml`` file, which could override any custom ``ConfigMap``
configuration, installing these files separately allows upgrade to be staged
and for user configuration to not be affected by the upgrade.

Rolling Back
============

Occasionally, it may be necessary to undo the rollout because a step was missed
or something went wrong during upgrade. To undo the rollout, change the image
tag back to the previous version or undo the rollout using ``kubectl``:

.. code-block:: shell-session

    $ kubectl rollout undo daemonset/cilium -n kube-system

This will revert the latest changes to the Cilium ``DaemonSet`` and return
Cilium to the state it was in prior to the upgrade.

.. note::

    When rolling back after new features of the new minor version have already
    been consumed, consult an eventual existing downgrade section in the
    :ref:`version_notes` to check and prepare for incompatible feature use
    before downgrading/rolling back. This step is only required after new
    functionality introduced in the new minor version has already been
    explicitly used by importing policy or by opting into new features via the
    `ConfigMap`.

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

+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+
| Current version       | Target version        | ``DaemonSet`` upgrade | L3 impact               | L7 impact                 |
+=======================+=======================+=======================+=========================+===========================+
| ``1.0.x``             | ``1.1.y``             | Required              | N/A                     | Clients must reconnect[1] |
+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.1.x``             | ``1.2.y``             | Required              | Temporary disruption[2] | Clients must reconnect[1] |
+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.2.x``             | ``1.3.y``             | Required              | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+
| ``>=1.2.5``           | ``1.5.y``             | Required              | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.5.x``             | ``1.6.y``             | Required              | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+-----------------------+-------------------------+---------------------------+

Annotations:

#. **Clients must reconnect**: Any traffic flowing via a proxy (for example,
   because an L7 policy is in place) will be disrupted during upgrade.
   Endpoints communicating via the proxy must reconnect to re-establish
   connections.

#. **Temporary disruption**: All traffic may be temporarily disrupted during
   upgrade. Connections should successfully re-establish without requiring
   clients to reconnect.

.. _1.6_upgrade_notes:

1.6 Upgrade Notes
-----------------

Upgrading from >=1.5.0 to 1.6.y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Follow the standard procedures to perform the upgrade as described in
   :ref:`upgrade_minor`. Users running older versions should first upgrade to
   the latest v1.5.x point release to minimize disruption of service
   connections during upgrade.

Changes that may require action
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  * The CNI configuration file auto-generated by Cilium
    (``/etc/cni/net.d/05-cilium.conf``) is now always automatically overwritten
    unless the environment variable ``CILIUM_CUSTOM_CNI_CONF`` is set in which
    case any already existing configuration file is untouched.

  * The new default value for the option ``monitor-aggregation`` is now
    ``medium`` instead of ``none``. This will cause the BPF datapath to
    perform more aggressive aggregation on packet forwarding related events to
    reduce CPU consumption while running ``cilium monitor``. The automatic
    change only applies to the default ConfigMap. Existing deployments will
    need to change the setting in the ConfigMap explicitly.

  * Any new Cilium deployment on Kubernetes using the default ConfigMap will no
    longer fetch the container runtime specific labels when an endpoint is
    created and solely rely on the pod, namespace and ServiceAccount labels.
    Previously, Cilium also scraped labels from the container runtime which we
    are also pod labels and prefixed those with ``container:``. We have seen
    less and less use of container runtime specific labels by users so it is no
    longer justified for every deployment to pay the cost of interacting with
    the container runtime by default. Any new deployment wishing to apply
    policy based on container runtime labels, must change the ConfigMap option
    ``container-runtime`` to ``auto`` or specify the container runtime to use.

    Existing deployments will continue to interact with the container runtime
    to fetch labels which are known to the runtime but not known to Kubernetes
    as pod labels. If you are not using container runtime labels, consider
    disabling it to reduce resource consumption on each by setting the option
    ``container-runtime`` to ``none`` in the ConfigMap.

New ConfigMap Options
~~~~~~~~~~~~~~~~~~~~~

  * ``cni-chaining-mode`` has been added to automatically generate CNI chaining
    configurations with various other plugins. See the section
    :ref:`cni_chaining` for a list of supported CNI chaining plugins.

Deprecated options
~~~~~~~~~~~~~~~~~~

* ``enable-legacy-services``: This option was introduced to ease the transition
  between Cilium 1.4.x and 1.5.x releases, allowing smooth upgrade and
  downgrade. As of 1.6.0, it is deprecated. Subsequently downgrading from 1.6.x
  or later to 1.4.x may result in disruption of connections that connect via
  services.

Deprecated metrics
~~~~~~~~~~~~~~~~~~

* ``policy_l7_parse_errors_total``: Use ``policy_l7_total`` instead.
* ``policy_l7_forwarded_total``: Use ``policy_l7_total`` instead.
* ``policy_l7_denied_total``: Use ``policy_l7_total`` instead.
* ``policy_l7_received_total``: Use ``policy_l7_total`` instead.

.. _1.5_upgrade_notes:

1.5 Upgrade Notes
-----------------

Upgrading from >=1.4.0 to 1.5.y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. In v1.4, the TCP conntrack table size ``ct-global-max-entries-tcp``
   ConfigMap parameter was ineffective due to a bug and thus, the default
   value (``1000000``) was used instead. To prevent from breaking established
   TCP connections, ``bpf-ct-global-tcp-max`` must be set to ``1000000`` in
   the ConfigMap before upgrading. Refer to the section :ref:`upgrade_configmap`
   on how to upgrade the `ConfigMap`.

#. If you previously upgraded to v1.5, downgraded to <v1.5, and now want to
   upgrade to v1.5 again, then you must run the following `DaemonSet` before
   doing the upgrade:

    .. tabs::
      .. group-tab:: K8s 1.10

        .. parsed-literal::

          $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-pre-flight-with-rm-svc-v2.yaml

      .. group-tab:: K8s 1.11

        .. parsed-literal::

          $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-pre-flight-with-rm-svc-v2.yaml

      .. group-tab:: K8s 1.12

        .. parsed-literal::

          $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-pre-flight-with-rm-svc-v2.yaml

      .. group-tab:: K8s 1.13

        .. parsed-literal::

          $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-pre-flight-with-rm-svc-v2.yaml

      .. group-tab:: K8s 1.14

        .. parsed-literal::

          $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.14/cilium-pre-flight-with-rm-svc-v2.yaml

      .. group-tab:: K8s 1.15

        .. parsed-literal::

          $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.15/cilium-pre-flight-with-rm-svc-v2.yaml


   See :ref:`pre_flight` for instructions how to run, validate and remove
   a pre-flight `DaemonSet`.

#. Follow the standard procedures to perform the upgrade as described in :ref:`upgrade_minor`.

New Default Values
~~~~~~~~~~~~~~~~~~

 * The connection-tracking garbage collector interval is now dynamic. It will
   automatically  adjust based n on the percentage of the connection tracking
   table that has been cleared in the last run. The interval will vary between
   10 seconds and 30 minutes or 12 hours for LRU based maps. This should
   automatically optimize CPU consumption as much as possible while keeping the
   connection tracking table utilization below 25%. If needed, the interval can
   be set to a static interval with the option ``--conntrack-gc-interval``. If
   connectivity fails and ``cilium monitor --type drop`` shows ``xx drop (CT:
   Map insertion failed)``, then it is likely that the connection tracking
   table is filling up and the automatic adjustment of the garbage collector
   interval is insufficient. Set ``--conntrack-gc-interval`` to an interval
   lower than the default.  Alternatively, the value for
   ``bpf-ct-global-any-max`` and ``bpf-ct-global-tcp-max`` can be increased.
   Setting both of these options will be a trade-off of CPU for
   ``conntrack-gc-interval``, and for ``bpf-ct-global-any-max`` and
   ``bpf-ct-global-tcp-max`` the amount of memory consumed.

.. _1.5_new_options:

New ConfigMap Options
~~~~~~~~~~~~~~~~~~~~~

  All options available in the cilium-agent can now be specified in the Cilium
  ConfigMap without requiring to set an environment variable in the DaemonSet.

  * ``enable-k8s-event-handover``: enables use of the kvstore to optimize
    Kubernetes event handling by listening for k8s events in the operator and
    mirroring it into the kvstore for reduced overhead in large clusters.

  * ``enable-legacy-services``: enables legacy services (prior v1.5) to prevent
    from terminating established connections to services when upgrading Cilium
    from < v1.5 to v1.5. When the option is not disabled, legacy services are
    enabled by default. Legacy services need to stay enabled until a user is
    confident that they will not need to downgrade to < v1.5 anymore. Disabling
    and then enabling legacy services is not possible without breaking the
    established connections from `Pod` to `Service`.

Deprecated Options
~~~~~~~~~~~~~~~~~~

  * ``--conntrack-garbage-collector-interval`` has been deprecated. Please
    use the option ``--conntrack-gc-interval`` which parses a duration as
    string instead of a integer in seconds. Support for the deprecated option
    will be removed in 1.6.

  * ``legacy-host-allows-world`` option is now removed as planned.

  * ``monitor-aggregation-level``: Superseded by ``monitor-aggregation``.

  * ``ct-global-max-entries-tcp``: Superseded by ``bpf-ct-global-tcp-max``.

  * ``ct-global-max-entries-other``: Superseded by ``bpf-ct-global-any-max``.

  * ``prometheus-serve-addr`` from the ``cilium-metrics-config`` ConfigMap is
    superseded by ``prometheus-serve-addr`` from the ``cilium-config`` ConfigMap.

  * ``--auto-ipv6-node-routes`` was removed as planned. Use
    ``--auto-direct-node-routes`` instead.

.. _1.4_upgrade_notes:

1.4 Upgrade Notes
-----------------

Upgrading from >=1.3.0 to 1.4.y
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Follow the standard procedures to perform the upgrade as described in :ref:`upgrade_minor`.

.. note:: v1.3 of Cilium has reached end of life, and is no longer supported.
          v1.4 is still supported, but will only contain critical security fixes
          as of the release of v1.6.

Changes that may require action
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 * The ``--serve`` option was removed from cilium-bugtool in favor of a much
   reduced binary size. If you want to continue using the option, please use an
   older version of the cilium-bugtool binary.

 * The :ref:`DNS Polling` option used by ``toFQDNs.matchName`` rules is
   disabled by default in 1.4.x due to :ref:`limitations in the implementation
   <DNS Polling>`. It has been replaced by :ref:`DNS Proxy <DNS Proxy>` support, which must
   be explicitly enabled via changes to the policy described below. To ease
   upgrade, users may opt to enable the :ref:`DNS Polling` in v1.4.x by adding
   the ``--tofqdns-enable-poller`` option to cilium-agent without changing
   policies. For instructions on how to safely upgrade see
   :ref:`dns_upgrade_poller`.

 * The DaemonSet now uses ``dnsPolicy: ClusterFirstWithHostNet`` in order for
   Cilium to look up Kubernetes service names via DNS. This in turn requires
   the cluster to run a cluster DNS such as kube-dns or CoreDNS. If you are not
   running cluster DNS, remove the ``dnsPolicy`` field. This will mean that you
   cannot use the etcd-operator.
   More details can be found in the :ref:`k8s_req_kubedns` section.

.. _1.4_new_options:

New ConfigMap Options
~~~~~~~~~~~~~~~~~~~~~

  * ``enable-ipv4``: If ``true``, all endpoints are allocated an IPv4 address.

  * ``enable-ipv6``: If ``true``, all endpoints are allocated an IPv6 address.

  * ``preallocate-bpf-maps``: If ``true``, reduce per-packet latency at the expense
    of up-front memory allocation for entries in BPF maps. If this value is
    modified, then during the next Cilium startup the restore of existing
    endpoints and tracking of ongoing connections may be disrupted. This may
    lead to policy drops or a change in loadbalancing decisions for a
    connection for some time. Endpoints may need to be recreated to restore
    connectivity. If this option is set to ``false`` during an upgrade to 1.4.0
    or later, then it may cause one-time disruptions during the upgrade.

  * ``auto-direct-node-routes``: If ``true``, then enable automatic L2 routing
    between nodes. This is useful when running in direct routing mode and can
    be used as an alternative to running a routing daemon. Routes to other
    Cilium managed nodes will then be installed on automatically.

  * ``install-iptables-rules``: If set to ``false`` then Cilium will not
    install any iptables rules which are mainly for interaction with
    kube-proxy. By default it is set to ``true``.

  * ``masquerade``: The agent can optionally be set up for masquerading all
    network traffic leaving the main networking device if ``masquerade`` is
    set to ``true``. By default it is set to ``false``.

  * ``datapath-mode``: Cilium can operate in two different datapath modes,
    that is, either based upon ``veth`` devices (default) or ``ipvlan``
    devices (beta). The latter requires an additional setting to specify
    the ipvlan master device.

  * New ipvlan-specific CNI integration mode options (beta):

    * ``ipvlan-master-device``: When running Cilium in ipvlan datapath mode,
      an ipvlan master device must be specified. This is typically pointing
      to a networking device that is facing the external network. Be aware
      that this will be used by all nodes, so it is required that the device
      name is consistent on all nodes where this is going to be deployed.

  * New flannel-specific CNI integration mode options (beta):

    * ``flannel-master-device``: When running Cilium with policy enforcement
      enabled on top of Flannel, the BPF programs will be installed on the
      network interface specified in this option and on each network interface
      belonging to a pod.

    * ``flannel-uninstall-on-exit``: If ``flannel-master-device`` is specified,
      this determines whether Cilium should remove BPF programs from the master
      device and interfaces belonging to pods when the Cilium `DaemonSet` is
      deleted. If true, Cilium will remove programs from the pods.

    * ``flannel-manage-existing-containers``: On startup, install a BPF
      programs to allow for policy enforcement on pods that are currently
      managed by Flannel. This also requires the Cilium `DaemonSet` to be
      running with ``hostPID: true``, which is not enabled by default.

Deprecated ConfigMap Options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* ``disable-ipv4``: Superseded by ``enable-ipv4``, with the logic reversed.

* ``legacy-host-allows-world``: This option allowed users to specify Cilium
  1.0-style policies that treated traffic that is masqueraded from the outside
  world as though it arrived from the local host. As of Cilium 1.4, the option
  is disabled by default if not specified in the ConfigMap, and the option is
  scheduled to be removed in Cilium 1.5 or later.


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

Upgrading a ConfigMap
---------------------

This section describes the procedure to upgrade an existing `ConfigMap` to the
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
            # In case you want to use TLS in etcd, uncomment the 'ca-file' line
            # and create a kubernetes secret by following the tutorial in
            # https://cilium.link/etcd-config
            ca-file: '/var/lib/etcd-secrets/etcd-client-ca.crt'
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
``true``, it has a etcd endpoint running with `TLS <https://coreos.com/etcd/docs/latest/op-guide/security.html>`_,
and the etcd is set up to have `client to server authentication <https://coreos.com/etcd/docs/latest/op-guide/security.html#example-2-client-to-server-authentication-with-https-client-certificates>`_.

Download the ConfigMap with the changes for |SCM_BRANCH|
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. tabs::
  .. group-tab:: K8s 1.10

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-cm.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-cm.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-cm.yaml

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-cm.yaml

  .. group-tab:: K8s 1.14

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.14/cilium-cm.yaml

  .. group-tab:: K8s 1.15

    .. parsed-literal::

      $ wget \ |SCM_WEB|\/examples/kubernetes/1.15/cilium-cm.yaml

Verify its contents:

.. literalinclude:: ../../examples/kubernetes/1.15/cilium-cm.yaml

Add new options
~~~~~~~~~~~~~~~

Add the new options manually to your old `ConfigMap`, and make the necessary
changes.

In this example, the ``debug`` option is meant to be kept with ``true``, the
``etcd-config`` is kept unchanged, and ``legacy-host-allows-world`` is a new
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
          legacy-host-allows-world: "false"
          etcd-config: |-
            ---
            endpoints:
            - https://192.168.33.11:2379
            #
            # In case you want to use TLS in etcd, uncomment the 'ca-file' line
            # and create a kubernetes secret by following the tutorial in
            # https://cilium.link/etcd-config
            ca-file: '/var/lib/etcd-secrets/etcd-client-ca.crt'
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

::

        $ kubectl apply -n kube-system -f ./cilium-cm-old.yaml

As the `ConfigMap` is successfully upgraded we can start upgrading Cilium
``DaemonSet`` and ``RBAC`` which will pick up the latest configuration from the
`ConfigMap`.


.. _cidr_limitations:

Restrictions on unique prefix lengths for CIDR policy rules
-----------------------------------------------------------

The Linux kernel applies limitations on the complexity of BPF code that is
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


.. _dns_upgrade_poller:

Upgrading :ref:`DNS Polling` deployments to :ref:`DNS Proxy`
---------------------------------------------------------------------

In cilium versions 1.2 and 1.3 :ref:`DNS Polling` was automatically used to
obtain IP information for use in ``toFQDNs.matchName`` rules in :ref:`DNS Based`
policies.
Cilium 1.4 and later have switched to a :ref:`DNS Proxy <DNS Proxy>` scheme - the
:ref:`DNS Polling` behaviour may be enabled via the a CLI option - and expect a
pod to make a DNS request that can be intercepted. Existing pods may have
already-cached DNS lookups that the proxy cannot intercept and thus cilium will
block these on upgrade. New connections with DNS requests that can be
intercepted will be allowed per-policy without special action.
Cilium deployments already configured with :ref:`DNS Proxy <DNS Proxy>` rules are not
impacted and will retain DNS data when restarted or upgraded.

Affected versions
~~~~~~~~~~~~~~~~~

* Cilium 1.2 and 1.3 when using :ref:`DNS Polling` with ``toFQDNs.matchName``
  policy rules and upgrading to cilium 1.4.0 or later.
* Cilium 1.4 or later that do not yet have L7 :ref:`DNS Proxy` policy rules.

Mitigation
~~~~~~~~~~

Deployments that require a seamless transition to :ref:`DNS Proxy <DNS Proxy>`
may use :ref:`pre_flight` to create a copy of DNS information on each cilium
node for use by the upgraded cilium-agent at startup. This data is used to
allow L3 connections (via ``toFQDNs.matchName`` and ``toFQDNs.matchPattern``
rules) without a DNS request from pods.
:ref:`pre_flight` accomplishes this via the ``--tofqdns-pre-cache`` CLI option,
which reads DNS cache data for use on startup.

Solution
~~~~~~~~

DNS data obtained via polling must be recorded for use on startup and rules
added to intercept DNS lookups. The steps are split into a section on
seamlessly upgrading :ref:`DNS Polling` and then further beginning to intercept
DNS data via a :ref:`DNS Proxy <DNS Proxy>`.

Policy rules may be prepared to use the :ref:`DNS Proxy <DNS Proxy>` before an
upgrade to 1.4. The new policy rule fields ``toFQDNs.matchPattern`` and
``toPorts.rules.dns.matchName/matchPattern`` will be ignored by older cilium
versions and can be safely implemented prior to an upgrade.

The following example allows DNS access to ``kube-dns`` via the :ref:`DNS Proxy
<DNS Proxy>` and allows all DNS requests to ``kube-dns``. For completeness,
``toFQDNs`` rules are included for examples of the syntax for those L3 policies
as well. Existing ``toFQDNs`` rules do not need to be modified but will now use
IPs seen by DNS requests and allowed by the ``toFQDNs.matchPattern`` rule.

.. only:: html

   .. tabs::
     .. group-tab:: k8s YAML

        .. literalinclude:: ../../examples/policies/l7/dns/dns-upgrade.yaml
     .. group-tab:: JSON

        .. literalinclude:: ../../examples/policies/l7/dns/dns-upgrade.json

.. only:: epub or latex

        .. literalinclude:: ../../examples/policies/l7/dns/dns-upgrade.json


Upgrade steps - :ref:`DNS Polling`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Set the ``tofqdns-enable-poller`` field to true in the cilium ConfigMap used
   in the upgrade. Alternatively, pass ``--tofqdns-enable-poller=true`` to
   the upgraded cilium-agent.

#. Add ``tofqdns-pre-cache: "/var/run/cilium/dns-precache-upgrade.json"``
   to the ConfigMap. Alternatively, pass
   ``--tofqdns-pre-cache="/var/run/cilium/dns-precache-upgrade.json"`` to
   cilium-agent.

#. Deploy the cilium :ref:`pre_flight` helper. This will download the cilium
   container image and also create DNS pre-cache data at
   ``/var/run/cilium/dns-precache-upgrade.json``. This data will have a TTL of
   1 week.

#. Deploy the new cilium DaemonSet

#. (optional) Remove ``tofqdns-pre-cache: "/var/run/cilium/dns-precache-upgrade.json"``
   from the cilium ConfigMap. The data will automatically age-out after 1 week.

Conversion steps - :ref:`DNS Proxy`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#. Update existing policies to intercept DNS requests.
   See :ref:`dns_discovery` or the example above

#. Allow pods to make DNS requests to populate the cilium-agent cache. To check
   which exact queries are in the DNS cache and when they will expire use
   ``cilium fqdn cache list``

#. Set the ``tofqdns-enable-poller`` field to false in the cilium ConfigMap

#. Restart the cilium pods with the new ConfigMap. They will restore Endpoint
   policy with DNS information from intercepted DNS requests stored in the
   cache

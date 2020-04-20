.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _admin_upgrade:

*************
Upgrade Guide
*************

.. _upgrade_general:

This upgrade guide is intended for Cilium running on Kubernetes. Helm
commands in this guide use helm3 syntax. If you have questions, feel
free to ping us on the `Slack channel`.

.. include:: upgrade-warning.rst

.. _pre_flight:

Running pre-flight check (Required)
===================================

When rolling out an upgrade with Kubernetes, Kubernetes will first terminate the
pod followed by pulling the new image version and then finally spin up the new
image. In order to reduce the downtime of the agent, the new image version can
be pre-pulled. It also verifies that the new image version can be pulled and
avoids ErrImagePull errors during the rollout. If you are running in :ref:`kubeproxy-free`
mode you need to also pass on the Kubernetes API Server IP and /
or the Kubernetes API Server Port when generating the ``cilium-preflight.yaml``
file.

.. tabs::
  .. group-tab:: kubectl

    .. parsed-literal::

      helm template |CHART_RELEASE| \\
        --set preflight.enabled=true \\
        --set agent.enabled=false \\
        --set config.enabled=false \\
        --set operator.enabled=false \\
        > cilium-preflight.yaml
      kubectl create cilium-preflight.yaml

  .. group-tab:: Helm

    .. parsed-literal::

      helm install cilium-preflight |CHART_RELEASE| \\
        --namespace=kube-system \\
        --set preflight.enabled=true \\
        --set agent.enabled=false \\
        --set config.enabled=false \\
        --set operator.enabled=false

  .. group-tab:: kubectl (kubeproxy-free)

    .. parsed-literal::

      helm template |CHART_RELEASE| \\
        --set preflight.enabled=true \\
        --set agent.enabled=false \\
        --set config.enabled=false \\
        --set operator.enabled=false \\
        --set global.k8sServiceHost=API_SERVER_IP \\
        --set global.k8sServicePort=API_SERVER_PORT \\
        > cilium-preflight.yaml
      kubectl create cilium-preflight.yaml

  .. group-tab:: Helm (kubeproxy-free)

    .. parsed-literal::

      helm install cilium-preflight |CHART_RELEASE| \\
        --namespace=kube-system \\
        --set preflight.enabled=true \\
        --set agent.enabled=false \\
        --set config.enabled=false \\
        --set operator.enabled=false \\
        --set global.k8sServiceHost=API_SERVER_IP \\
        --set global.k8sServicePort=API_SERVER_PORT

After running the cilium-pre-flight.yaml, make sure the number of READY pods
is the same number of Cilium pods running.

.. code-block:: shell-session

    kubectl get daemonset -n kube-system | grep cilium
    NAME                      DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR   AGE
    cilium                    2         2         2       2            2           <none>          1h20m
    cilium-pre-flight-check   2         2         2       2            2           <none>          7m15s

Once the number of READY pods are the same, make sure the Cilium PreFlight
deployment is also marked as READY 1/1. In case it shows READY 0/1 please see
:ref:`cnp_validation`.

.. code-block:: shell-session

    kubectl get deployment -n kube-system cilium-pre-flight-check -w
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

    .. parsed-literal::

      kubectl delete -f cilium-preflight.yaml

  .. group-tab:: Helm

    .. parsed-literal::

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

Step 2: Option A: Generate YAML using Helm (Recommended)
--------------------------------------------------------

Since Cilium version 1.6, `Helm` is used to generate the YAML file for
deployment. This allows to regenerate the entire YAML from scratch using the
same option sets as used for the initial deployment while ensuring that all
Kubernetes resources are updated accordingly to version you are upgrading to:

.. include:: ../gettingstarted/k8s-install-download-release.rst

.. tabs::
  .. group-tab:: kubectl

    Generate the required YAML file and deploy it:

    .. parsed-literal::

      helm template |CHART_RELEASE| \\
        --namespace kube-system \\
        > cilium.yaml
      kubectl apply -f cilium.yaml

  .. group-tab:: Helm

    Deploy Cilium release via Helm:

    .. parsed-literal::

      helm upgrade cilium |CHART_RELEASE| --namespace=kube-system

.. note::

   Make sure that you are using the same options as for the initial deployment.
   Instead of using ``--set``, you can also modify the ``values.yaml` in
   ``install/kubernetes/cilium/values.yaml`` and use it to regenerate the YAML
   for the latest version.

Step 2: Option B: Preserve ConfigMap
------------------------------------

Alternatively, you can use `Helm` to regenerate all Kubernetes resources except
for the `ConfigMap`. The configuration of Cilium is stored in a `ConfigMap`
called ``cilium-config``. The format is compatible between minor releases so
configuration parameters are automatically preserved across upgrades. However,
new minor releases may introduce new functionality that require opt-in via the
`ConfigMap`. Refer to the :ref:`upgrade_version_specifics` for a list of new
configuration options for each minor version.

.. include:: ../gettingstarted/k8s-install-download-release.rst

.. tabs::
  .. group-tab:: kubectl

    Generate the required YAML file and deploy it:

    .. parsed-literal::

      helm template |CHART_RELEASE| \\
        --namespace kube-system \\
        --set config.enabled=false \\
        > cilium.yaml
      kubectl apply -f cilium.yaml

  .. group-tab:: Helm

    Deploy Cilium release via Helm:

    .. parsed-literal::

      helm upgrade cilium |CHART_RELEASE| \\
        --namespace=kube-system \\
        --set config.enabled=false

.. note::

   The above variant can not be used in combination with ``--set`` or providing
   ``values.yaml`` because all options are fed into the DaemonSets and
   Deployments using the `ConfigMap` which is not generated if
   ``config.enabled=false`` is set. The above command *only* generates the
   DaemonSet, Deployment and RBAC definitions.

Step 3: Rolling Back
====================

Occasionally, it may be necessary to undo the rollout because a step was missed
or something went wrong during upgrade. To undo the rollout run:

.. tabs::
  .. group-tab:: kubectl

    .. parsed-literal::

      kubectl rollout undo daemonset/cilium -n kube-system

  .. group-tab:: Helm

    .. parsed-literal::

      helm history cilium --namespace=kube-system
      helm rollback cilium [REVISION] --namespace=kube-system

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

+-----------------------+-----------------------+------------------+-------------------------+---------------------------+
| Current version       | Target version        | Full YAML update | L3 impact               | L7 impact                 |
+=======================+=======================+==================+=========================+===========================+
| ``1.0.x``             | ``1.1.y``             | Required         | N/A                     | Clients must reconnect[1] |
+-----------------------+-----------------------+------------------+-------------------------+---------------------------+
| ``1.1.x``             | ``1.2.y``             | Required         | Temporary disruption[2] | Clients must reconnect[1] |
+-----------------------+-----------------------+------------------+-------------------------+---------------------------+
| ``1.2.x``             | ``1.3.y``             | Required         | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+------------------+-------------------------+---------------------------+
| ``>=1.2.5``           | ``1.5.y``             | Required         | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+------------------+-------------------------+---------------------------+
| ``1.5.x``             | ``1.6.y``             | Required         | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+------------------+-------------------------+---------------------------+
| ``1.6.x``             | ``1.6.6``             | Not required     | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+------------------+-------------------------+---------------------------+
| ``1.6.x``             | ``1.6.7``             | Required         | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+------------------+-------------------------+---------------------------+
| ``1.6.x``             | ``1.7.y``             | Required         | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+------------------+-------------------------+---------------------------+
| ``1.7.0``             | ``1.7.1``             | Required         | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+------------------+-------------------------+---------------------------+
| ``>=1.7.1``           | ``1.7.y``             | Not required     | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+------------------+-------------------------+---------------------------+

Annotations:

#. **Clients must reconnect**: Any traffic flowing via a proxy (for example,
   because an L7 policy is in place) will be disrupted during upgrade.
   Endpoints communicating via the proxy must reconnect to re-establish
   connections.

#. **Temporary disruption**: All traffic may be temporarily disrupted during
   upgrade. Connections should successfully re-establish without requiring
   clients to reconnect.

.. _1.7_upgrade_notes:

1.7 Upgrade Notes
-----------------

.. _current_release_required_changes:

.. _1.7_required_changes:

IMPORTANT: Changes required before upgrading to 1.7.x
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::

   Do not upgrade to 1.7.x before reading the following section and completing
   the required steps.

   In particular, if you are using network policy and upgrading from 1.6.x or earlier
   to 1.7.x or later, you MUST read the 1.7 :ref:`configmap_remote_node_identity`
   section about the
   ``enable-remote-node-identity`` flag to avoid potential disruption
   to connectivity between host networking pods and Cilium-managed pods.

* Cilium has bumped the minimal kubernetes version supported to v1.11.0.

* The ``kubernetes.io/cluster-service`` label has been removed from the Cilium
  `DaemonSet` selector. Existing users must either choose to keep this label in
  `DaemonSet` specification to safely upgrade or re-create the Cilium `DaemonSet`
  without the deprecated label. It is advisable to keep the label when doing
  an upgrade from ``v1.6.x`` to ``v1.7.x`` in the event of having to do a
  downgrade. The removal of this label should be done after a successful
  upgrade.

  The helm option ``agent.keepDeprecatedLabels=true`` will keep the
  ``kubernetes.io/cluster-service`` label in the new `DaemonSet`:

.. tabs::
  .. group-tab:: kubectl

    .. parsed-literal::

      helm template cilium \
      --namespace=kube-system \
      ...
      --set agent.keepDeprecatedLabels=true \
      ...
      > cilium.yaml
      kubectl apply -f cilium.yaml

  .. group-tab:: Helm

    .. parsed-literal::

      helm upgrade cilium --namespace=kube-system \
      --set agent.keepDeprecatedLabels=true


  Trying to upgrade Cilium without this option might result in the following
  error: ``The DaemonSet "cilium" is invalid: spec.selector: Invalid value: ...: field is immutable``


* If ``kvstore`` is setup with ``etcd`` **and** TLS is enabled, the field name
  ``ca-file`` will have its usage deprecated and will be removed in Cilium v1.8.0.
  The new field name, ``trusted-ca-file``, can be used since Cilium v1.1.0.

  *Required action:*

  This field name should be changed from ``ca-file`` to ``trusted-ca-file``.

  Example of an old etcd configuration, with the ``ca-file`` field name:

  .. code:: yaml

    ---
    endpoints:
    - https://192.168.0.1:2379
    - https://192.168.0.2:2379
    ca-file: '/var/lib/cilium/etcd-ca.pem'
    # In case you want client to server authentication
    key-file: '/var/lib/cilium/etcd-client.key'
    cert-file: '/var/lib/cilium/etcd-client.crt'

  Example of new etcd configuration, with the ``trusted-ca-file`` field name:

  .. code:: yaml

    ---
    endpoints:
    - https://192.168.0.1:2379
    - https://192.168.0.2:2379
    trusted-ca-file: '/var/lib/cilium/etcd-ca.pem'
    # In case you want client to server authentication
    key-file: '/var/lib/cilium/etcd-client.key'
    cert-file: '/var/lib/cilium/etcd-client.crt'

* Due to the removal of external libraries to connect to container runtimes,
  Cilium no longer supports the option ``flannel-manage-existing-containers``.
  Cilium will still support integration with Flannel for new containers
  provisioned but not for containers already running in Flannel. The options
  ``container-runtime`` and ``container-runtime-endpoint`` will not have any
  effect and the flag removal is scheduled for v1.8.0

* The default ``--tofqdns-min-ttl`` value has been reduced to 1 hour. Specific
  IPs in DNS entries are no longer expired when in-use by existing connections
  that are allowed by policy. Prior deployments that used the default value may
  now experience denied new connections if endpoints reuse DNS data more than 1
  hour after the initial lookup without making new lookups. Long lived
  connections that previously outlived DNS entries are now better supported,
  and will not be disconnected when the corresponding DNS entry expires.

.. _configmap_remote_node_identity:

New ConfigMap Options
~~~~~~~~~~~~~~~~~~~~~

  * ``enable-remote-node-identity`` has been added to enable a new identity
    for remote cluster nodes and to associate all IPs of a node with that new
    identity. This allows for network policies that distinguish between
    connections from host networking pods or other processes on the local
    Kubernetes worker node from those on remote worker nodes.

    After enabling this option, all communication to and from non-local
    Kubernetes nodes must be whitelisted with a ``toEntity`` or ``fromEntity``
    rule listing the entity ``remote-node``. The existing entity ``cluster``
    continues to work and now includes the entity ``remote-node``.  Existing
    policy rules whitelisting ``host`` will only affect the local node going
    forward. Existing CIDR-based rules to whitelist node IPs other than the
    Cilium internal IP (IP assigned to the ``cilium_host`` interface), will no
    longer take effect.

    This is important because Kubernetes Network Policy dictates that network
    connectivity from the local host must always be allowed, even for pods that
    have a default deny rule for ingress connectivity.   This is so that
    network liveness and readiness probes from kubelet will not be dropped by
    network policy.  Prior to 1.7.x, Cilium achieved this by always allowing
    ingress host network connectivity from any host in the cluster.  With 1.7
    and ``enable-remote-node-identity=true``, Cilium will only automatically
    allow connectivity from the local node, thereby providing a better default
    security posture.

    The option is enabled by default for new deployments when generated via
    Helm, in order to gain the benefits of improved security. The Helm option
    is ``--set global.remoteNodeIdentity``. This option can be disabled in
    order to maintain full compatibility with Cilium 1.6.x policy enforcement.
    **Be aware** that upgrading a cluster to 1.7.x by using helm to generate a
    new Cilium config that leaves ``enable-remote-node-identity`` set as the
    default value of ``true`` **can break network connectivity.**

    The reason for this is that
    with Cilium 1.6.x, the source identity of ANY connection from a host-networking pod or from
    other processes on a Kubernetes worker node would be the  ``host`` identity.   Thus, a
    Cilium 1.6.x or earlier environment with network policy enforced may be implicitly
    relying on the ``allow everything from host identity`` behavior to
    whitelist traffic from host networking to other Cilium-managed pods.
    With the shift to 1.7.x, if ``enable-remote-node-identity=true``
    these connections will be denied by policy if they are coming from
    a host-networking pod or process on another Kubernetes worker node, since the source
    will be given the ``remote-node`` identity (which is not automatically
    allowed) rather than the ``host`` identity (which is automatically allowed).

    An indicator that this is happening would be drops visible in Hubble or
    Cilium monitor with a source identity equal to 6 (the numeric value for the
    new ``remote-node`` identity.   For example:

    ::

       xx drop (Policy denied) flow 0x6d7b6dd0 to endpoint 1657, identity 6->51566: 172.16.9.243:47278 -> 172.16.8.21:9093 tcp SYN

    There are two ways to address this.  One can set
    ``enable-remote-node-identity=false`` in the `ConfigMap` to retain the
    Cilium 1.6.x behavior.  However, this is not ideal, as it means there is no
    way to prevent communication between host-networking pods and
    Cilium-managed pods, since all such connectivity is allowed automatically
    because it is from the ``host`` identity.

    The other option is to keep ``enable-remote-node-identity=true`` and
    create policy rules that explicitly whitelist connections between
    the ``remote-host`` identity and pods that should be reachable from host-networking pods
    or other processes that may be running on a remote Kubernetes worker node.   An example of
    such a rule is:


    ::

       apiVersion: "cilium.io/v2"
       kind: CiliumNetworkPolicy
       metadata:
         name: "allow-from-remote-nodes"
       spec:
         endpointSelector:
           matchLabels:
             app: myapp
         ingress:
         - fromEntities:
           - remote-node

    See :ref:`policy-remote-node` for more examples of remote-node policies.


  * ``enable-well-known-identities`` has been added to control the
    initialization of the well-known identities. Well-known identities have
    initially been added to support the managed etcd concept to allow the etcd
    operator to bootstrap etcd while Cilium still waited on etcd to become
    available. Cilium now uses CRDs by default which limits the use of
    well-known identities to the managed etcd mode. With the addition of this
    option, well-known identities are disabled by default in all new deployment
    and only enabled if the Helm option ``etcd.managed=true`` is set. Consider
    disabling this option if you are not using the etcd operator respectively
    managed etcd mode to reduce the number of policy identities whitelisted for
    each endpoint.

  * ``kube-proxy-replacement`` has been added to control which features should
    be enabled for the kube-proxy BPF replacement. The option is set to
    ``probe`` by default for new deployments when generated via Helm. This
    makes cilium-agent to probe for each feature support in a kernel, and
    to enable only supported features. When the option is not set via Helm,
    cilium-agent defaults to ``partial``. This makes ``cilium-agent`` to
    enable only those features which user has explicitly enabled in their
    ConfigMap. See :ref:`kubeproxy-free` for more option values.

    For users who previously were running with ``nodePort.enabled=true`` it is
    recommended to set the option to ``strict`` before upgrading.

  * ``enable-auto-protect-node-port-range`` has been added to enable
    auto-appending of a NodePort port range to
    ``net.ipv4.ip_local_reserved_ports`` if it overlaps with an ephemeral port
    range from ``net.ipv4.ip_local_port_range``. The option is enabled by
    default. See :ref:`kubeproxy-free` for the explanation why the overlap can
    be harmful.

Modified Options
~~~~~~~~~~~~~~~~

* ``api-server-port``: This flag, available in cilium-operator deployment only,
  changed its behavior in v1.7.1 and later. The old behavior was opening that
  port on all interfaces, the new behavior is opening that port on
  ``127.0.0.1`` and ``::1`` only. No action is necessary to handle this change
  during upgrade.

Removed options
~~~~~~~~~~~~~~~~~~

* ``lb``: The ``--lb`` feature has been removed. If you need load-balancing on
  a particular device, consider using :ref:`kubeproxy-free`.

* ``docker`` and ``e``: This flags has been removed as Cilium no longer requires
  container runtime integrations to manage containers' networks.

* All code associated with ``monitor v1.0`` socket handling has been removed.

.. _1.6_upgrade_notes:

1.6 Upgrade Notes
-----------------

.. _1.6_required_changes:

IMPORTANT: Changes required before upgrading to 1.6.0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::

   Do not upgrade to 1.6.0 before reading the following section and completing
   the required steps.

* The ``kvstore`` and ``kvstore-opt`` options have been moved from the
  `DaemonSet` into the `ConfigMap`. For many users, the DaemonSet definition
  was not considered to be under user control as the upgrade guide requests to
  apply the latest definition. Doing so for 1.6.0 without adding these options
  to the `ConfigMap` which is under user control would result in those settings
  to refer back to its default values.

  *Required action:*

  Add the following two lines to the ``cilium-config`` `ConfigMap`:

  .. code:: bash

     kvstore: etcd
     kvstore-opt: '{"etcd.config": "/var/lib/etcd-config/etcd.config"}'

  This will preserve the existing behavior of the DaemonSet. Adding the options
  to the `ConfigMap` will not impact the ability to rollback. Cilium 1.5.y and
  earlier are compatible with the options although their values will be ignored
  as both options are defined in the `DaemonSet` definitions for these versions
  which takes precedence over the `ConfigMap`.

* **Downgrade warning:** Be aware that if you want to change the
  ``identity-allocation-mode`` from ``kvstore`` to ``crd`` in order to no
  longer depend on the kvstore for identity allocation, then a
  rollback/downgrade requires you to revert that option and it will result in
  brief disruptions of all connections as identities are re-created in the
  kvstore.

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

  * ``identity-allocation-mode`` has been added to allow selecting the identity
    allocation method. The default for new deployments is ``crd`` as per
    default ConfigMap. Existing deployments will continue to use ``kvstore``
    unless opted into new behavior via the ConfigMap.

Deprecated options
~~~~~~~~~~~~~~~~~~

* ``enable-legacy-services``: This option was introduced to ease the transition
  between Cilium 1.4.x and 1.5.x releases, allowing smooth upgrade and
  downgrade. As of 1.6.0, it is deprecated. Subsequently downgrading from 1.6.x
  or later to 1.4.x may result in disruption of connections that connect via
  services.

* ``lb``: The ``--lb`` feature has been deprecated. It has not been in use and
  has not been well tested. If you need load-balancing on a particular device,
  ping the development team on Slack to discuss options to get the feature
  fully supported.

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

          $ kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/v1.5/examples/kubernetes/1.10/cilium-pre-flight-with-rm-svc-v2.yaml

      .. group-tab:: K8s 1.11

        .. parsed-literal::

          $ kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/v1.5/examples/kubernetes/1.11/cilium-pre-flight-with-rm-svc-v2.yaml

      .. group-tab:: K8s 1.12

        .. parsed-literal::

          $ kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/v1.5/examples/kubernetes/1.12/cilium-pre-flight-with-rm-svc-v2.yaml

      .. group-tab:: K8s 1.13

        .. parsed-literal::

          $ kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/v1.5/examples/kubernetes/1.13/cilium-pre-flight-with-rm-svc-v2.yaml

      .. group-tab:: K8s 1.14

        .. parsed-literal::

          $ kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/v1.5/examples/kubernetes/1.14/cilium-pre-flight-with-rm-svc-v2.yaml

      .. group-tab:: K8s 1.15

        .. parsed-literal::

          $ kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/v1.5/examples/kubernetes/1.15/cilium-pre-flight-with-rm-svc-v2.yaml


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
``true``, it has a etcd endpoint running with `TLS <https://coreos.com/etcd/docs/latest/op-guide/security.html>`_,
and the etcd is set up to have `client to server authentication <https://coreos.com/etcd/docs/latest/op-guide/security.html#example-2-client-to-server-authentication-with-https-client-certificates>`_.

Generate the latest ConfigMap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

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


Migrating from kvstore-backed identities to kubernetes CRD-backed identities
----------------------------------------------------------------------------

Beginning with cilium 1.6, kubernetes CRD-backed security identities can be
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

.. code:: bash

    helm template cilium \
      --namespace=kube-system \
      --set preflight.enabled=true \
      --set agent.enabled=false \
      --set config.enabled=false \
      --set operator.enabled=false \
      --set global.etcd.enabled=true \
      --set global.etcd.ssl=true \
      > cilium-preflight.yaml
    kubectl create cilium-preflight.yaml


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

  .. parsed-literal::

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

Start by deployment the ``cilium-pre-flight-check`` and check if the the
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
commit these changes into kubernetes.

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
policies so that kubernetes creates a new pod immediately to verify if the fixed
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

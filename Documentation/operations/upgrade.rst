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
from ``1.11.x`` to ``1.12.y`` first, and to ``1.13.z`` only afterwards).

+-----------------------+-----------------------+-------------------------+---------------------------+
| Current version       | Target version        | L3/L4 impact            | L7 impact                 |
+=======================+=======================+=========================+===========================+
| ``1.12.x``            | ``1.13.y``            | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.11.x``            | ``1.12.y``            | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+-------------------------+---------------------------+
| ``1.10.x``            | ``1.11.y``            | Minimal to None         | Clients must reconnect[1] |
+-----------------------+-----------------------+-------------------------+---------------------------+

Annotations:

#. **Clients must reconnect**: Any traffic flowing via a proxy (for example,
   because an L7 policy is in place) will be disrupted during upgrade.
   Endpoints communicating via the proxy must reconnect to re-establish
   connections.

.. _current_release_required_changes:

.. _1.14_upgrade_notes:

1.14 Upgrade Notes
------------------
* The default value of ``--tofqdns-min-ttl`` has changed from 3600 seconds to
  zero. This means Cilium DNS network policy now honors the TTLs returned from
  the upstream DNS server by default. Explicitly configure ``--tofqdns-min-ttl``
  if you need to preserve the previous DNS network policy behavior that lets
  applications create new connections after the TTL specified by the upstream
  DNS server is expired.
* Cilium now writes its CNI configuration file to ``05-cilium.conflist`` in
  all cases, rather than the previous default of ``05-cilium.conf``.
* The default value of ``--update-ec2-adapter-limit-via-api`` has changed from
  ``false`` to ``true``. This means that the Cilium Operator will fetch the
  most up-to-date EC2 adapter limits from the AWS API. This now requires
  updated IAM permissions for Cilium to have ``ec2:DescribeInstances``. In EKS,
  nodes usually have ``AmazonEKSWorkerNodePolicy`` which includes this
  permission, so it should work in most cases. If your nodes don't have this
  policy, then consider adding it to your IAM permissions. Explicitly configure
  ``--update-ec2-adapter-limit-via-api`` to ``false`` if you want to avoid this
  additional IAM permission. Beware that if your EC2 instance type that Cilium
  is running on is not known to Cilium, it may cause a crash.
* Egress Gateway policies now drop matching traffic when no
  gateway nodes can be found. Previously, traffic would be allowed without
  being rerouted towards an Egress Gateway.
* If Gateway API feature is enabled, please upgrade related CRDs to v0.6.x. This is
  mainly for ReferenceGrant resource version change (i.e. from v1alpha2 to v1beta1).

Removed Options
~~~~~~~~~~~~~~~

* The ``sockops-enable`` and ``force-local-policy-eval-at-source`` options deprecated in version
  1.13 are removed.

New Options
~~~~~~~~~~~

* ``routing-mode=native``: This option enables native-routing mode, in place of
  ``tunnel=disabled``, now deprecated.
* ``tunnel-protocol``: This option allows setting the tunneling protocol, in place
  of e.g., ``tunnel=vxlan``.

Deprecated Options
~~~~~~~~~~~~~~~~~~

* The ``tunnel`` option is deprecated and will be removed in v1.15. To enable
  native-routing mode, set ``routing-mode=native`` (previously
  ``tunnel=disabled``). To configure the tunneling protocol, set
  ``tunnel-protocol=geneve`` (previously ``tunnel=geneve``).

Added Metrics
~~~~~~~~~~~~~

* ``cilium_operator_ces_sync_total``
* ``cilium_policy_change_total``
* ``go_sched_latencies_seconds``
* ``cilium_operator_ipam_available_ips``
* ``cilium_operator_ipam_used_ips``
* ``cilium_operator_ipam_needed_ips``

Deprecated Metrics
~~~~~~~~~~~~~~~~~~

* ``cilium_operator_ces_sync_errors_total`` is deprecated. Please use ``cilium_operator_ces_sync_total`` instead.
* ``cilium_policy_import_errors_total`` is deprecated. Please use
  ``cilium_policy_change_total``, which counts all policy changes (Add, Update, Delete)
  based on outcome ("success" or "failure").
* ``cilium_operator_ipam_ips`` is deprecated. Use ``cilium_operator_ipam_{available,used,needed}_ips`` instead.

Changed Metrics
~~~~~~~~~~~~~~~

* ``cilium_bpf_map_pressure`` is now enabled by default.

Helm Options
~~~~~~~~~~~~

* The ``securityContext`` for Hubble Relay now applies to the container, not
  the pod. To update the security context of the pod, use
  ``podSecurityContext``.
* The ``securityContext`` for Hubble Relay now defaults to drop all
  capabilities and run as non-root user.
* The ``containerRuntime.integration`` value is being deprecated in favor of ``bpf.autoMount.enabled``.
* Following the deprecation of the ``tunnel`` agent flag, ``tunnel`` is being
  deprecated in favor of ``routingMode`` and ``tunnelProtocol`` and will be
  removed in v1.15.
* Values ``encryption.keyFile``, ``encryption.mountPath``,
  ``encryption.secretName`` and ``encryption.interface`` are deprecated in
  favor of their ``encryption.ipsec.*`` counterparts and will be removed in
  Cilium 1.15.
* Value ``hubble.peerService.enabled`` was deprecated in Cilium 1.13 and has
  been removed. The peer service is no longer optional.
* Values ``hubble.tls.ca``, ``hubble.tls.ca.cert`` and ``hubble.tls.ca.key``
  were deprecated in Cilium 1.12 in favor of ``tls.ca``, ``tls.ca.cert`` and
  ``tls.ca.key`` respectively, and have been removed.
* Value ``hubble.ui.securityContext.enabled`` was deprecated in Cilium 1.12 in
  favor of ``hubble.ui.securityContext``, and has been removed.
* Values ``ipam.operator.clusterPoolIPv4PodCIDR`` and
  ``ipam.operator.clusterPoolIPv6PodCIDR`` were deprecated in Cilium 1.11 in
  favor of ``ipam.operator.clusterPoolIPv4PodCIDRList`` and
  ``ipam.operator.clusterPoolIPv6PodCIDRList``, respectively, and have been
  removed.
  In order to preserve the default behavior for selecting CIDRs when default
  values are kept, ``ipam.operator.clusterPoolIPv4PodCIDRList`` now defaults to
  a singleton containing the default CIDR value for the removed value
  ``ipam.operator.clusterPoolIPv4PodCIDR`` (and similarly for IPv6).
* Values ``clustermesh.apiserver.tls.ca.cert`` and ``clustermesh.apiserver.tls.ca.key``
  are deprecated in favor of ``tls.ca.cert`` and ``tls.ca.key`` respectively, and
  will be removed in v1.15.
* Values ``proxy.prometheus.enabled`` and ``proxy.prometheus.port`` are deprecated in favor of
  their ``envoy.prometheus.*`` counterparts.

.. _earlier_upgrade_notes:

Earlier Upgrade Notes
---------------------

For upgrades from earlier releases, see the
:prev-docs:`upgrade notes from the previous version <operations/upgrade/#upgrade-notes>`.

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

      $ kubectl exec -n kube-system cilium-pre-flight-check-1234 -- cilium preflight migrate-identity
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
      $ kubectl exec -n kube-system cilium-1234 -- cilium endpoint list # existing etcd-backed endpoints

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

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

    .. cilium-helm-template::
       :namespace: kube-system
       :set: preflight.enabled=true
             agent=false
             operator.enabled=false
       :post-helm-commands: > cilium-preflight.yaml
       :post-commands: kubectl create -f cilium-preflight.yaml

  .. group-tab:: Helm

    .. cilium-helm-install::
       :name: cilium-preflight
       :namespace: kube-system
       :set: preflight.enabled=true
             agent=false
             operator.enabled=false

  .. group-tab:: kubectl (kubeproxy-free)

    .. cilium-helm-template::
       :namespace: kube-system
       :set: preflight.enabled=true
             agent=false
             operator.enabled=false
             k8sServiceHost=API_SERVER_IP
             k8sServicePort=API_SERVER_PORT
       :post-helm-commands: > cilium-preflight.yaml
       :post-commands: kubectl create -f cilium-preflight.yaml

  .. group-tab:: Helm (kubeproxy-free)

    .. cilium-helm-install::
       :name: cilium-preflight
       :namespace: kube-system
       :set: preflight.enabled=true
             agent=false
             operator.enabled=false
             k8sServiceHost=API_SERVER_IP
             k8sServicePort=API_SERVER_PORT

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

    .. cilium-helm-template::
       :namespace: kube-system
       :set: upgradeCompatibility=1.X
       :post-helm-commands: > cilium.yaml
       :post-commands: kubectl apply -f cilium.yaml

  .. group-tab:: Helm

    Deploy Cilium release via Helm:

    .. cilium-helm-upgrade::
       :namespace: kube-system
       :set: upgradeCompatibility=1.X

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

   .. cilium-helm-upgrade::
      :namespace: kube-system
      :extra-args: -f my-values.yaml

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

.. _1.20_upgrade_notes:

1.20 Upgrade Notes
------------------

Action Required
~~~~~~~~~~~~~~~

If you are using the following features in your environment, then you may need
to take action because of changes to the behavior of these features. Read the
notes carefully below to understand what to do during upgrade.

* TODO

Informational Notes
~~~~~~~~~~~~~~~~~~~

* TODO

Changes to Features
~~~~~~~~~~~~~~~~~~~

New Options
###########

The following options have been introduced in this version of Cilium:

* ``bpf.datapathMode=auto`` config option has been introduced. If set, Cilium will probe
  the underlying host for netkit support and, if found, netkit mode will be selected at
  runtime. Otherwise, Cilium will default back to the standard veth mode. This has the
  side effect of splitting the datapath-mode into "configured mode" and "operational mode"
  in status outputs, where they differ. The default remains ``bpf.datapathMode=veth``
  but may change in future releases.
* ``bpf.tproxy=true`` is incompatible with netkit datapath mode. If netkit is also enabled,
  Cilium will fail to start. If auto-detect datapath mode is used, Cilium will revert to
  veth mode, even if netkit support is present.

Changed Options
###############

The following options have been modified in this version of Cilium to behave
differently than in prior releases:

* TODO

Deprecated Options
##################

The following options have been deprecated in this version of Cilium. A future
version of Cilium will remove these options, so if you use these options then
you may need to take action to migrate to an alternative.

* TODO

Removed Options
###############

The following options were previously deprecated, and they are now removed
from Cilium.

* TODO

Changes to Metrics
~~~~~~~~~~~~~~~~~~

Added Metrics
#############

* TODO

Changed Metrics
###############

* TODO

Deprecated Metrics
##################

* TODO

Removed Metrics
###############

* TODO

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


Migrating from kvstore-backed identities to Kubernetes CRD-backed identities
----------------------------------------------------------------------------

Beginning with Cilium 1.6, Kubernetes CRD-backed security identities can be
used for smaller clusters. Along with other changes in 1.6, this allows
kvstore-free operation if desired. It is possible to migrate identities from an
existing kvstore deployment to CRD-backed identities. This minimizes
disruptions to traffic as the update rolls out through the cluster.

Migration
~~~~~~~~~

When identities change, existing connections can be disrupted while Cilium
initializes and synchronizes with the shared identity store. The disruption
occurs when new numeric identities are used for existing pods on some instances
and others are used on others. When converting to CRD-backed identities, it is
possible to pre-allocate CRD identities so that the numeric identities match
those in the kvstore. This allows new and old Cilium instances in the rollout
to agree.

There are two ways to achieve this: you can either run a one-off ``cilium preflight migrate-identity`` script
which will perform a point-in-time copy of all identities from the kvstore to CRDs (added in Cilium 1.6), or use the "Double Write" identity
allocation mode which will have Cilium manage identities in both the kvstore and CRD at the same time for a seamless migration (added in Cilium 1.17).

Migration with the ``cilium preflight migrate-identity`` script
###############################################################

The ``cilium preflight migrate-identity`` script is a one-off tool that can be used to copy identities from the kvstore into CRDs.
It has a couple of limitations:

* If an identity is created in the kvstore after the one-off migration has been completed, it will not be copied into a CRD.
  This means that you need to perform the migration on a cluster with no identity churn.
* There is no easy way to revert back to ``--identity-allocation-mode=kvstore`` if something goes wrong after
  Cilium has been migrated to ``--identity-allocation-mode=crd``

If these limitations are not acceptable, it is recommended to use the ":ref:`Double Write <double_write_migration>`" identity allocation mode instead.

The following steps show an example of performing the migration using the ``cilium preflight migrate-identity`` script.
It is safe to re-run the command if desired. It will identify already allocated identities or ones that
cannot be migrated. Note that identity ``34815`` is migrated, ``17003`` is
already migrated, and ``11730`` has a conflict and a new ID allocated for those
labels.

The steps below assume a stable cluster with no new identities created during
the rollout. Once Cilium using CRD-backed identities is running, it may begin
allocating identities in a way that conflicts with older ones in the kvstore.

The cilium preflight manifest requires etcd support and can be built with:

.. cilium-helm-template::
   :namespace: kube-system
   :set: preflight.enabled=true
         agent=false
         config.enabled=false
         operator.enabled=false
         etcd.enabled=true
         etcd.ssl=true
   :post-helm-commands: > cilium-preflight.yaml
   :post-commands: kubectl create -f cilium-preflight.yaml


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

If a migration has gone wrong, it possible to start with a clean slate. Ensure that no Cilium instances are running with ``--identity-allocation-mode=crd`` and execute:

.. code-block:: shell-session

      $ kubectl delete ciliumid --all

.. _double_write_migration:

Migration with the "Double Write" identity allocation mode
##########################################################

.. include:: ../beta.rst

The "Double Write" Identity Allocation Mode allows Cilium to allocate identities as KVStore values *and* as CRDs at the
same time. This mode also has two versions: one where the source of truth comes from the kvstore (``--identity-allocation-mode=doublewrite-readkvstore``),
and one where the source of truth comes from CRDs (``--identity-allocation-mode=doublewrite-readcrd``).

The high-level migration plan looks as follows:

#. Starting state: Cilium is running in KVStore mode.
#. Switch Cilium to "Double Write" mode with all reads happening from the KVStore. This is almost the same as the
   pure KVStore mode with the only difference being that all identities are duplicated as CRDs but are not used.
#. Switch Cilium to "Double Write" mode with all reads happening from CRDs. This is equivalent to Cilium running in
   pure CRD mode but identities will still be updated in the KVStore to allow for the possibility of a fast rollback.
#. Switch Cilium to CRD mode. The KVStore will no longer be used and will be ready for decommission.

This will allow you to perform a gradual and seamless migration with the possibility of a fast rollback at steps two or three.

Furthermore, when the "Double Write" mode is enabled, the Operator will emit additional metrics to help monitor the
migration progress. These metrics can be used for alerting about identity inconsistencies between the KVStore and CRDs.

Note that you can also use this to migrate from CRD to KVStore mode. All operations simply need to be repeated in reverse order.

Rollout Instructions
~~~~~~~~~~~~~~~~~~~~

#. Re-deploy first the Operator and then the Agents with ``--identity-allocation-mode=doublewrite-readkvstore``.
#. Monitor the Operator metrics and logs to ensure that all identities have converged between the KVStore and CRDs. The relevant metrics emitted by the Operator are:

   * ``cilium_operator_identity_crd_total_count`` and ``cilium_operator_identity_kvstore_total_count`` report the total number of identities in CRDs and KVStore respectively.
   * ``cilium_operator_identity_crd_only_count`` and ``cilium_operator_identity_kvstore_only_count`` report the number of
     identities that are only in CRDs or only in the KVStore respectively, to help detect inconsistencies.

   In case further investigation is needed, the Operator logs will contain detailed information about the discrepancies between KVStore and CRD identities.
   Note that Garbage Collection for KVStore identities and CRD identities happens at slightly different times, so it is possible to see discrepancies in the metrics
   for certain periods of time, depending on ``--identity-gc-interval`` and ``--identity-heartbeat-timeout`` settings.
#. Once all identities have converged, re-deploy the Operator and the Agents with ``--identity-allocation-mode=doublewrite-readcrd``.
   This will cause Cilium to read identities only from CRDs, but continue to write them to the KVStore.
#. Once you are ready to decommission the KVStore, re-deploy first the Agents and then the Operator with ``--identity-allocation-mode=crd``.
   This will make Cilium read and write identities only to CRDs.
#. You can now decommission the KVStore.

.. _change_policy_default_local_cluster:

Preparing for a ``policy-default-local-cluster`` change
#######################################################

Cilium network policies used to implicitly select endpoints from all the clusters.
Cilium 1.18 introduced a new option called ``policy-default-local-cluster`` which
will be set by default in Cilium 1.19. This option restricts endpoints selection to
the local cluster by default. If you are using ClusterMesh and network policies this
will be a **breaking change** and you **need to take action** before upgrading to
Cilium 1.19.

This new option can be set in the ConfigMap or via the Helm value ``clustermesh.policyDefaultLocalCluster``.
You can set ``policy-default-local-cluster`` to ``false`` in Cilium 1.19 to keep the existing behavior,
however this option will be deprecated and eventually removed in a future release so you should plan your
migration to set ``policy-default-local-cluster`` to ``true``.

Migrating network policies in practice
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The command ``cilium clustermesh inspect-policy-default-local-cluster --all-namespaces`` can help you
discover all the policies that will change as a result of changing ``policy-default-local-cluster``.
You can also replace ``--all-namespaces`` with ``-n my-namespace`` if you want to only inspect
policies from a particular namespace.

Below is an example where there is one network policy that needs to be updated:

.. code-block:: shell-session

    $ cilium clustermesh inspect-policy-default-local-cluster --all-namespaces

    ⚠️ CiliumNetworkPolicy 0/1
            ⚠️ default/allow-from-bar

    ✅ CiliumClusterWideNetworkPolicy 0/0

    ✅ NetworkPolicy 0/0


In this situation you have only one CiliumNetworkPolicy which is affected by a
``policy-default-local-cluster`` change. Let's take a look at the policy:

.. code-block:: yaml

    apiVersion: "cilium.io/v2"
    kind: CiliumNetworkPolicy
    metadata:
      name: allow-from-bar
      namespace: default
    spec:
      description: "Allow ingress traffic from bar"
      endpointSelector:
        matchLabels:
          name: foo
      ingress:
      - fromEndpoints:
        - matchLabels:
            name: bar

This network policy does not explicitly select a cluster. This means that with ``policy-default-local-cluster``
set to ``false`` it allows traffic coming from ``bar`` in any clusters connected in your ClusterMesh.
With ``policy-default-local-cluster`` set to ``true``, this policy allows traffic from ``bar`` from only
the local cluster instead.

If ``foo`` and ``bar`` are always in the same cluster, no further action is necessary.

In case you want to do this on this individual policy rather than at a global level or that
``bar`` is located on a remote cluster you can update your policy like that:

.. code-block:: yaml

    apiVersion: "cilium.io/v2"
    kind: CiliumNetworkPolicy
    metadata:
      name: allow-from-bar
      namespace: default
    spec:
      description: "Allow ingress traffic from bar"
      endpointSelector:
        matchLabels:
          name: foo
      ingress:
      - fromEndpoints:
        - matchLabels:
            name: bar
            io.cilium.k8s.policy.cluster: fixme-cluster-name

If ``bar`` is located in multiple cluster you can also use a ``matchExpressions``
selecting multiple clusters like that:

.. code-block:: yaml

    apiVersion: "cilium.io/v2"
    kind: CiliumNetworkPolicy
    metadata:
      name: allow-from-bar
      namespace: default
    spec:
      description: "Allow ingress traffic from bar"
      endpointSelector:
        matchLabels:
          name: foo
      ingress:
      - fromEndpoints:
        - matchLabels:
            name: bar
          matchExpressions:
            - key: io.cilium.k8s.policy.cluster
              operator: In
              values:
                - fixme-cluster-name-1
                - fixme-cluster-name-2

Alternatively, you can also allow traffic from ``bar`` located in every cluster and restore
the same behavior as setting ``policy-default-local-cluster`` to ``false`` but on this
individual policy:

.. code-block:: yaml

    apiVersion: "cilium.io/v2"
    kind: CiliumNetworkPolicy
    metadata:
      name: allow-from-bar
      namespace: default
    spec:
      description: "Allow ingress traffic from bar"
      endpointSelector:
        matchLabels:
          name: foo
      ingress:
      - fromEndpoints:
        - matchLabels:
            name: bar
          matchExpressions:
            - key: io.cilium.k8s.policy.cluster
              operator: Exists

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

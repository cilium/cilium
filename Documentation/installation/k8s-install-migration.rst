.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _cni_migration:

*************************************
Migrating a cluster to Cilium
*************************************

Cilium can be used to migrate from another cni. Running clusters can
be migrated on a node-by-node basis, without disrupting existing traffic
or requiring a complete cluster outage or rebuild depending on the complexity of the migration case.

This document outlines how migrations with Cilium work. You will have a good
understanding of the basic requirements, as well as see an example migration
which you can practice using :ref:`Kind <gs_kind>`.


Background
==========

When the kubelet creates a Pod's Sandbox, the installed CNI, as configured in ``/etc/cni/net.d/``,
is called. The cni will handle the networking for a pod - including allocating 
an ip address, creating & configuring a network interface, and (potentially)
establishing an overlay network. The Pod's network configuration shares the
same life cycle as the PodSandbox.

In the case of migration, we typically reconfigure ``/etc/cni/net.d/`` to point
to Cilium. However, any existing pods will still have been configured by the old
network plugin and any new pods will be configured by the newer CNI. To complete
the migration all Pods on the cluster that are configured by the old cni must be
recycled in order to be a member of the new CNI.

A naive approach to migrating a CNI would be to reconfigure all nodes with a new
CNI and then gradually restart each node in the cluster, thus replacing the CNI
when the node is brought back up and ensuring that all pods are part of the new CNI.

This simple migration, while effective, comes at the cost of disrupting cluster
connectivity during the rollout. Unmigrated and migrated nodes would be split in
to two "islands" of connectivity, and pods would be randomly unable to reach one-another
until the migration is complete.

Migration via dual overlays
---------------------------

Instead, Cilium supports a *hybrid* mode, where two separate overlays are established
across the cluster. While pods on a given node can only be attached to one network,
they have access to both Cilium and non-Cilium pods while the migration is
taking place. As long as Cilium and the existing networking provider use a separate
IP range, the Linux routing table takes care of separating traffic.

In this document we will discuss a model for live migrating between two deployed
CNI implementations. This will have the benefit of reducing downtime of nodes
and workloads and ensuring that workloads on both configured CNIs can communicate
during migration.

For live migration to work, Cilium will be installed with a separate
CIDR range and encapsulation port than that of the currently installed CNI. As
long as Cilium and the existing CNI use a separate IP range, the Linux 
routing table takes care of separating traffic.



Requirements
============

Live migration requires the following:

- A new, distinct Cluster CIDR for Cilium to use
- Use of the :ref:`Cluster Pool IPAM mode<ipam_crd_cluster_pool>`
- A distinct overlay, either protocol or port
- An existing network plugin that uses the Linux routing stack, such as Flannel, Calico, or AWS-CNI

Limitations
===========

Currently, Cilium migration has not been tested with:

- BGP-based routing
- Changing IP families (e.g. from IPv4 to IPv6)
- Migrating from Cilium in chained mode
- An existing NetworkPolicy provider

During migration, Cilium's  NetworkPolicy and CiliumNetworkPolicy enforcement 
will be disabled. Otherwise, traffic from non-Cilium pods may be incorrectly
dropped. Once the migration process is complete, policy enforcement can
be re-enabled. If there is an existing NetworkPolicy provider, you may wish to
temporarily delete all NetworkPolicies before proceeding.

It is strongly recommended to install Cilium using the :ref:`cluster-pool <ipam_crd_cluster_pool>`
IPAM allocator. This provides the strongest assurance that there will
be no IP collisions.

.. warning::
  Migration is highly dependent on the exact configuration of existing
  clusters. It is, thus, strongly recommended to perform a trial migration
  on a test or lab cluster.

Overview
========

The migration process utilizes the :ref:`per-node configuration<per-node-configuration>`
feature to selectively enable Cilium CNI. This allows for a controlled rollout
of Cilium without disrupting existing workloads.

Cilium will be installed, first, in a mode where it establishes an overlay
but does not provide CNI networking for any pods. Then, individual nodes will
be migrated.

In summary, the process looks like:

1. Install cilium in "secondary" mode
2. Cordon, drain, migrate, and reboot each node
3. Remove the existing network provider
4. (Optional) Reboot each node again


Migration procedure
===================

Preparation
-----------

- Optional: Create a :ref:`Kind <gs_kind>` cluster and install `Flannel <https://github.com/flannel-io/flannel>`_ on it.

    .. parsed-literal::

      $ cat <<EOF > kind-config.yaml
      apiVersion: kind.x-k8s.io/v1alpha4
      kind: Cluster
      nodes:
      - role: control-plane
      - role: worker
      - role: worker
      networking:
        disableDefaultCNI: true
      EOF
      $ kind create cluster --config=kind-config.yaml
      $ kubectl apply -n kube-system --server-side -f \ |SCM_WEB|\/examples/misc/migration/install-reference-cni-plugins.yaml
      $ kubectl apply --server-side -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
      $ kubectl wait --for=condition=Ready nodes --all

- Optional: Monitor connectivity.

  You may wish to install a tool such as `goldpinger <https://github.com/bloomberg/goldpinger>`_
  to detect any possible connectivity issues.

1.  Select a **new** CIDR for pods. It must be distinct from all other CIDRs in use.

    For Kind clusters, the default is ``10.244.0.0/16``. So, for this example, we will
    use ``10.245.0.0/16``.

2.  Select a **distinct** encapsulation port. For example, if the existing cluster
    is using VXLAN, then you should either use GENEVE or configure Cilium to use VXLAN
    with a different port.

    For this example, we will use VXLAN with a non-default port of 8473.

3.  Create a helm ``values-migration.yaml`` file based on the following example. Be sure to fill
    in the CIDR you selected in step 1.

    .. code-block:: yaml

        operator:
          unmanagedPodWatcher:
            restart: false # Migration: Don't restart unmigrated pods
        routingMode: tunnel # Migration: Optional: default is tunneling, configure as needed
        tunnelProtocol: vxlan # Migration: Optional: default is VXLAN, configure as needed
        tunnelPort: 8473 # Migration: Optional, change only if both networks use the same port by default
        cni:
          customConf: true # Migration: Don't install a CNI configuration file
          uninstall: false # Migration: Don't remove CNI configuration on shutdown
        ipam:
          mode: "cluster-pool"
          operator:
            clusterPoolIPv4PodCIDRList: ["10.245.0.0/16"] # Migration: Ensure this is distinct and unused
        policyEnforcementMode: "never" # Migration: Disable policy enforcement
        bpf:
          hostLegacyRouting: true # Migration: Allow for routing between Cilium and the existing overlay

4.  Configure any additional Cilium Helm values.

    Cilium supports a number of :ref:`Helm configuration options<helm_reference>`. You may choose to
    auto-detect typical ones using the :ref:`cilium-cli <install_cilium_cli>`.
    This will consume the template and auto-detect any other relevant Helm values.
    Review these values for your particular installation.

    .. code-block:: shell-session

        $ cilium install --helm-values values-migration.yaml --helm-auto-gen-values values-initial.yaml
        $ cat values-initial.yaml


5.  Install cilium using :ref:`helm <k8s_install_helm>`.

    .. code-block:: shell-session

      $ helm repo add cilium https://helm.cilium.io/
      $ helm install cilium cilium/cilium --namespace kube-system --values values-initial.yaml


    At this point, you should have a cluster with Cilium installed and an overlay established, but no
    pods managed by Cilium itself. You can verify this with the ``cilium`` command.

    .. code-block:: shell-session

      $ cilium status --wait
      ...
      Cluster Pods:     0/3 managed by Cilium


6.  Create a :ref:`per-node config<per-node-configuration>` that will instruct Cilium to "take over" CNI networking
    on the node. Initially, this will apply to no nodes; you will roll it out gradually via
    the migration process.

    .. code-block:: shell-session

        cat <<EOF | kubectl apply --server-side -f -
        apiVersion: cilium.io/v2alpha1
        kind: CiliumNodeConfig
        metadata:
          namespace: kube-system
          name: cilium-default
        spec:
          nodeSelector:
            matchLabels:
              io.cilium.migration/cilium-default: "true"
          defaults:
            write-cni-conf-when-ready: /host/etc/cni/net.d/05-cilium.conflist
            custom-cni-conf: "false"
            cni-chaining-mode: "none"
            cni-exclusive: "true"
        EOF

Migration
---------

At this point, you are ready to begin the migration process. The basic flow is:

Select a node to be migrated. It is not recommended to start with a control-plane node.

.. code-block:: shell-session

  $ NODE="kind-worker" # for the Kind example

1.  Cordon and, optionally, drain the node in question.

    .. code-block:: shell-session

      $ kubectl cordon $NODE
      $ kubectl drain --ignore-daemonsets $NODE

    Draining is not strictly required, but it is recommended. Otherwise pods will encounter
    a brief interruption while the node is rebooted.

2.  Label the node. This causes the ``CiliumNodeConfig`` to apply to this node.

    .. code-block:: shell-session

      $ kubectl label node $NODE --overwrite "io.cilium.migration/cilium-default=true"

3.  Restart Cilium. This will cause it to write its CNI configuration file.

    .. code-block:: shell-session

      $ kubectl -n kube-system delete pod --field-selector spec.nodeName=$NODE -l k8s-app=cilium
      $ kubectl -n kube-system rollout status ds/cilium -w

4.  Reboot the node.

    If using kind, do so with docker:

    .. code-block:: shell-session
    
      docker restart $NODE

5.  Validate that the node has been successfully migrated.

    .. code-block:: shell-session

      $ cilium status --wait
      $ kubectl get -o wide node $NODE
      $ kubectl -n kube-system run --attach --rm --restart=Never verify-network \
        --overrides='{"spec": {"nodeName": "'$NODE'", "tolerations": [{"operator": "Exists"}]}}' \
        --image ghcr.io/nicolaka/netshoot:v0.8 -- /bin/bash -c 'ip -br addr && curl -s -k https://$KUBERNETES_SERVICE_HOST/healthz && echo'

    Ensure the IP address of the pod is in the Cilium CIDR(s) supplied above and that the apiserver
    is reachable.

6.  Uncordon the node.

    .. code-block:: shell-session

      $ kubectl uncordon $NODE


Once you are satisfied everything has been migrated successfully, select another unmigrated node in the cluster
and repeat these steps.

Post-migration
--------------

Perform these steps once the cluster is fully migrated.

1.  Ensure Cilium is healthy and that all pods have been migrated:

    .. code-block:: shell-session

      $ cilium status

2.  Update the Cilium configuration:

    - Cilium should be the primary CNI
    - NetworkPolicy should be enforced
    - The Operator can restart unmanaged pods
    - **Optional**: use :ref:`eBPF_Host_Routing`. Enabling this will cause a short connectivity 
      interruption on each node as the daemon restarts, but improves networking performance.

    You can do this manually, or via the ``cilium`` tool (this will not apply changes to the cluster):

    .. code-block:: shell-session

      $ cilium install --helm-values values-initial.yaml --helm-auto-gen-values values-final.yaml \
        --helm-set operator.unmanagedPodWatcher.restart=true --helm-set cni.customConf=false \
        --helm-set policyEnforcementMode=default \
        --helm-set bpf.hostLegacyRouting=false # optional, can cause brief interruptions
      $ diff values-initial.yaml values-final.yaml

    Then, apply the changes to the cluster:

    .. code-block:: shell-session

      $ helm upgrade --namespace kube-system cilium cilium/cilium --values values-final.yaml
      $ kubectl -n kube-system rollout restart daemonset cilium
      $ cilium status --wait

3.  Delete the per-node configuration:

    .. code-block:: shell-session

      $ kubectl delete -n kube-system ciliumnodeconfig cilium-default

4.  Delete the previous network plugin.

    At this point, all pods should be using Cilium for networking. You can easily verify this with ``cilium status``.
    It is now safe to delete the previous network plugin from the cluster.


    Most network plugins leave behind some resources, e.g. iptables rules and interfaces. These will be
    cleaned up when the node next reboots. If desired, you may perform a rolling reboot again.
.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _ipam_cluster_pool_to_multi_pool_migration:

Migrating from Cluster Scope to Multi-Pool
##########################################

This section describes how to migrate a running cluster from
:ref:`ipam_crd_cluster_pool` IPAM mode to :ref:`ipam_crd_multi_pool` IPAM mode.
The migration keeps the existing per-node PodCIDR allocations stable, so pods
keep their IP addresses and connectivity is not disrupted while the cluster is
being migrated.

During the migration, the Cilium operator converts each ``CiliumNode`` from the
cluster-pool representation in ``spec.ipam.podCIDRs`` to the multi-pool
representation in ``spec.ipam.pools.allocated``. Cilium agents can then be
restarted incrementally. Nodes that still run in cluster-pool mode and nodes
that already run in multi-pool mode can continue to serve pod connectivity
during this rolling restart.

Limitations
***********

The following limitations apply to the migration:

* The migration only supports moving from cluster-pool IPAM mode to multi-pool
  IPAM mode. In case of failure, no rollback is available.
* All pods with IPs allocated from cluster-pool IPAM are migrated to the
  default multi-pool IP pool. Existing pods are not distributed into different
  pools based on pod annotations, namespace annotations, or pool selectors.
* The default pool must be available to the operator when it performs the
  migration. You can either create a ``CiliumPodIPPool`` manually before
  restarting the operator, or let the operator create it on startup by setting
  the ``auto-create-cilium-pod-ip-pools`` option. With Helm, this option is
  configured through the ``ipam.operator.autoCreateCiliumPodIPPools`` value.
* The default pool must cover the cluster-pool CIDRs that are already allocated
  to nodes, and must use the same mask size as the existing cluster-pool
  allocation.
* The default pool name is ``default`` unless changed with the
  ``ipam-default-ip-pool`` option.
* The default pool name used for the migration must not be overwritten on a
  per-node basis through a ``CiliumNodeConfig``. If you need to use a
  non-default pool name, change it globally with the ``ipam-default-ip-pool``
  option when restarting the operator.

Migration Steps
***************

Use this high-level workflow for the migration:

1. Create the default ``CiliumPodIPPool``, or configure
   ``auto-create-cilium-pod-ip-pools`` so that the Cilium operator creates it
   when it starts.
2. Upgrade the Cilium Helm release to change the Cilium configuration from
   ``ipam: cluster-pool`` to ``ipam: multi-pool``, set the operator option
   ``enable-cluster-pool-to-multi-pool-migration`` to ``true``, and restart
   only the Cilium operator.
3. Wait until each ``CiliumNode`` has its existing PodCIDR listed under
   ``spec.ipam.pools.allocated``.
4. Restart the Cilium agents, all at once or incrementally.

Practical Example
*****************

The following example migrates a kind cluster with one control-plane node and
three worker nodes. The cluster starts in cluster-pool IPAM mode with
``10.0.0.0/8`` as the cluster-wide pool and ``/24`` per-node PodCIDRs.

Before the migration, each ``CiliumNode`` stores its per-node allocation in
``spec.ipam.podCIDRs``:

.. code-block:: shell-session

  $ kubectl get ciliumnode kind-worker -o yaml | yq .spec.ipam
  podCIDRs:
    - 10.0.3.0/24
  pools: {}

  $ kubectl get ciliumnode kind-worker2 -o yaml | yq .spec.ipam
  podCIDRs:
    - 10.0.0.0/24
  pools: {}

  $ kubectl get ciliumnode kind-worker3 -o yaml | yq .spec.ipam
  podCIDRs:
    - 10.0.1.0/24
  pools: {}

  $ kubectl get ciliumnode kind-control-plane -o yaml | yq .spec.ipam
  podCIDRs:
    - 10.0.2.0/24
  pools: {}

Upgrade the Cilium Helm release to switch to multi-pool IPAM mode and enable
the operator migration. This example uses
``ipam.operator.autoCreateCiliumPodIPPools`` to let the operator create the
``default`` ``CiliumPodIPPool`` with the same CIDR and per-node mask size used
by cluster-pool IPAM. The command updates the Cilium ConfigMap and restarts
only the Cilium operator:

.. code-block:: shell-session

  $ helm upgrade cilium cilium/cilium \
      --namespace kube-system \
      --reuse-values \
      --set ipam.mode=multi-pool \
      --set ipam.operator.autoCreateCiliumPodIPPools.default.ipv4.cidrs='{10.0.0.0/8}' \
      --set ipam.operator.autoCreateCiliumPodIPPools.default.ipv4.maskSize=24 \
      --set-string extraConfig.enable-cluster-pool-to-multi-pool-migration=true \
      --set operator.rollOutPods=true \
      --set rollOutCiliumPods=false

If you want to use a different default pool name for the migration, configure
it globally in the same Helm upgrade that restarts the operator, with
``--set-string extraConfig.ipam-default-ip-pool=<pool-name>``.

Wait for the operator to create the default pool:

.. code-block:: shell-session

  $ kubectl get ciliumpodippool default -o yaml
  apiVersion: cilium.io/v2alpha1
  kind: CiliumPodIPPool
  metadata:
    name: default
  spec:
    ipv4:
      cidrs:
      - 10.0.0.0/8
      maskSize: 24

After the operator performs the migration, each node has the same per-node CIDR
allocated from the default multi-pool IP pool:

.. code-block:: shell-session

  $ kubectl get ciliumnode kind-worker -o yaml | yq .spec.ipam
  pools:
    allocated:
      - cidrs:
          - 10.0.3.0/24
        pool: default

  $ kubectl get ciliumnode kind-worker2 -o yaml | yq .spec.ipam
  pools:
    allocated:
      - cidrs:
          - 10.0.0.0/24
        pool: default

  $ kubectl get ciliumnode kind-worker3 -o yaml | yq .spec.ipam
  pools:
    allocated:
      - cidrs:
          - 10.0.1.0/24
        pool: default

  $ kubectl get ciliumnode kind-control-plane -o yaml | yq .spec.ipam
  pools:
    allocated:
      - cidrs:
          - 10.0.2.0/24
        pool: default

Restart one Cilium agent. You can delete the agent pod directly, or select it by
node name:

.. code-block:: shell-session

  $ kubectl -n kube-system delete pod \
      --field-selector spec.nodeName=kind-worker \
      --selector="app.kubernetes.io/name=cilium-agent"

After the agent restarts, it runs in multi-pool IPAM mode and requests IPs from
the default pool while preserving the IPs of restored endpoints:

.. code-block:: shell-session

  $ kubectl get ciliumnode kind-worker -o yaml | yq .spec.ipam
  pools:
    allocated:
      - cidrs:
          - 10.0.3.0/24
        pool: default
    requested:
      - needed:
          ipv4-addrs: 16
        pool: default

  $ kubectl -n kube-system exec -ti cilium-qvz4n -- cilium-dbg status --all-addresses
  IPAM:                   IPv4: 1 IPAM pool(s) available,
  Allocated addresses:
    10.0.3.190 (router)
    10.0.3.203 (default/nginx-66686b6766-9v2sb [restored])
    10.0.3.240 (health)

Connectivity between nodes is maintained while some agents have already moved
to multi-pool mode and other agents are still running in cluster-pool mode:

.. code-block:: shell-session

  $ kubectl exec -ti nginx-66686b6766-9v2sb -- curl 10.0.0.30:80
  <!DOCTYPE html>
  <html>
  <head>
  <title>Welcome to nginx!</title>
  ...

  $ kubectl exec -ti nginx-66686b6766-ktpgn -- curl 10.0.3.203:80
  <!DOCTYPE html>
  <html>
  <head>
  <title>Welcome to nginx!</title>
  ...

New pods can also be scheduled during the rolling migration. Multi-pool agents
allocate new IPs from the migrated default pool, while cluster-pool agents
continue to use their existing cluster-pool allocations until they are
restarted:

.. code-block:: shell-session

  $ kubectl scale deployment nginx --replicas=8
  deployment.apps/nginx scaled

  $ kubectl get pods -o wide
  NAME                     READY   STATUS    RESTARTS   AGE   IP           NODE
  nginx-66686b6766-26jkc   1/1     Running   0          12s   10.0.3.209   kind-worker
  nginx-66686b6766-hcnlz   1/1     Running   0          12s   10.0.0.101   kind-worker2
  nginx-66686b6766-9v2sb   1/1     Running   0          21m   10.0.3.203   kind-worker
  nginx-66686b6766-ktpgn   1/1     Running   0          21m   10.0.0.30    kind-worker2
  ...

Continue restarting the remaining Cilium agents until all nodes run in multi-pool
IPAM mode:

.. code-block:: shell-session

  $ kubectl -n kube-system delete pod \
      --field-selector spec.nodeName=kind-worker2 \
      --selector="app.kubernetes.io/name=cilium-agent"

  $ kubectl -n kube-system delete pod \
      --field-selector spec.nodeName=kind-worker3 \
      --selector="app.kubernetes.io/name=cilium-agent"

  $ kubectl -n kube-system delete pod \
      --field-selector spec.nodeName=kind-control-plane \
      --selector="app.kubernetes.io/name=cilium-agent"

When the last agent has restarted, the cluster is running multi-pool IPAM. The
existing pod IPs remain stable in the default multi-pool IP pool.

After the migration is complete, you can extend the allocatable PodCIDRs by
adding CIDRs to the default pool (for guidance on changing an existing pool,
see :ref:`update_existing_ciliumpodippools`) or by creating additional pools.
This overcomes the limitation of cluster-pool IPAM mode, where adding additional
CIDRs to a node is not supported.

.. warning::

  Only schedule pods that reference a non-default pool after all Cilium agents
  have restarted in multi-pool IPAM mode. During the rolling migration,
  Kubernetes may schedule the pod onto a node whose Cilium agent still runs in
  cluster-pool IPAM mode, where the referenced pool is not available.

Create a new pool:

.. code-block:: yaml

  apiVersion: cilium.io/v2alpha1
  kind: CiliumPodIPPool
  metadata:
    name: test-pool
  spec:
    ipv4:
      cidrs:
      - 11.0.0.0/8
      maskSize: 24

Then create a pod that explicitly requests IPs from the new pool:

.. code-block:: yaml

  apiVersion: v1
  kind: Pod
  metadata:
    name: nginx-other-pool
    annotations:
      ipam.cilium.io/ip-pool: test-pool
  spec:
    containers:
      - name: nginx
        image: nginx
        ports:
          - containerPort: 80

Apply the resources:

.. code-block:: shell-session

  $ kubectl apply -f test-pool.yaml
  ciliumpodippool.cilium.io/test-pool created
  $ kubectl apply -f nginx-other-pool.yaml
  pod/nginx-other-pool created

The new pod receives an IP from the new pool:

.. code-block:: shell-session

  $ kubectl get pods -o wide
  NAME                     READY   STATUS    RESTARTS   AGE   IP           NODE
  nginx-other-pool         1/1     Running   0          28s   11.0.0.15    kind-worker
  ...

The node hosting the pod now has an allocation from both the migrated default
pool and the new pool:

.. code-block:: shell-session

  $ kubectl get ciliumnode kind-worker -o yaml | yq .spec.ipam
  pools:
    allocated:
      - cidrs:
          - 10.0.3.0/24
        pool: default
      - cidrs:
          - 11.0.0.0/24
        pool: test-pool
    requested:
      - needed:
          ipv4-addrs: 16
        pool: default
      - needed:
          ipv4-addrs: 1
        pool: test-pool

  $ kubectl -n kube-system exec -ti cilium-qvz4n -- cilium-dbg status --all-addresses
  IPAM:                   IPv4: 2 IPAM pool(s) available,
  Allocated addresses:
    10.0.3.190 (router)
    10.0.3.203 (default/nginx-66686b6766-9v2sb [restored])
    10.0.3.209 (default/nginx-66686b6766-26jkc)
    10.0.3.240 (health)
    test-pool/11.0.0.15 (default/nginx-other-pool)

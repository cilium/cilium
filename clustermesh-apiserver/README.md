# API server for Cilium ClusterMesh

Cilium uses a clustermesh-apiserver when multiple clusters are connected in clustermesh, or
when external workloads are connected to the Cilium cluster. If neither is used, then
clustermesh-apiserver is never required.

Since etcd is used in a clustermesh for data synchronization, an etcd server container
is deployed within clustermesh-apiserver pod.

When used in an External Workloads setup, it also creates a CiliumNode and
CiliumEndpoint resources for each workload name and allocates its identity.

Note: `ipv4-alloc-cidr` set in the CiliumExternalWorkload object spec is currently unused.
IP address tied to the CiliumEndpoint and CiliumNode is the one that is registered by
cilium-agent (IP address of the external workload).

The API server itself performs the following operations:

### K8s synchronization

It performs the job of synchronizing CiliumIdentites, CiliumEndpoints,
CiliumNodes and Kubernetes services from k8s datastore to the KVStore (etcd).

### Heartbeat update

Cilium's heartbeat path key stored in the KVStore is periodically updated by
the API server with the current time so that Cilium Agents can correctly
validate KVStore updates. The key for this heartbeat is
`cilium/.heartbeat`.

## Deploy the clustermesh-apiserver

Clustermesh-apiserver is automatically deployed when External
Workloads support or clustermesh is enabled using either Helm or the cilium-cli tool.

Users are required to set both `cluster.name` and a non-zero `cluster.id` in Helm or
`cilium install --cluster-name <name> --cluster-id <id>`. Otherwise, clustermesh will
not be correctly established.

`clustermesh-apiserver` service type defaults to `NodePort`. Depending on
your k8s provider it may be beneficial to change this to `LoadBalancer`.

### Deploy using cilium-cli:

   ```
   $ cilium clustermesh enable
   ```

#### Connect Cilium clusters in to a clustermesh

   ```
   $ cilium --context "${CONTEXT1}" clustermesh connect --destination-context "${CONTEXT2}"
   ```
   Note: `clustermesh connect` command needs to be run for every new cluster (context) that joins clustermesh.

#### Wait for clustermesh status to be ready

   ```
   $ cilium --context "${CONTEXT1}" clustermesh status --wait
   ```

### Deploy using helm:

   ```
   $ helm install cilium ... \
     --set clustermesh.useAPIServer=true \
   ```

Additionally, if your load balancer can give you a static IP address, it may be
specified like so:

   ```
   $ helm install cilium ... \
     --set clustermesh.apiserver.service.loadBalancerIP=xxx.xxx.xxx.xxx \
   ```

Clustermesh-apiserver is deployed as a standard k8s deployment with multiple
containers. You can check that both clustermesh-apiserver and etcd server are present:

   ```
   $ kubectl get pods -l k8s-app=clustermesh-apiserver \
     -o jsonpath='{range .items[*].spec.containers[*]}{.image}{"\n"}{end}'
   quay.io/coreos/etcd:v3.5.4
   quay.io/cilium/clustermesh-apiserver:v1.10.2
   ```
#### Connect Cilium clusters in to a clustermesh

In helm installation clusters have to be connected in 2 steps:

1. Extract a `cilium-clustermesh` secret from each cluster to be applied in another cluster:

   ```
   $ contrib/k8s/k8s-extract-clustermesh-nodeport-secret.sh > cluster1-secret.json
   ```

   Repeat this step in all your clusters, storing the outputs into different files.

3. Apply secrets from all other clusters in each of your clusters, e.g., on cluster1:

   ```
   $ contrib/k8s/k8s-import-clustermesh-secrets.sh cluster2-secret.json cluster3-secret.json ...
   ```

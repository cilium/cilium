# API server for Cilium ClusterMesh

## Deploy the clustermesh-apiserver

Cilium Helm charts automatically deploy clustermesh-apiserver when Cilium
cluster.name is not "default". Remember to set a non-zero cluster.id in Helm as
well. `clustermesh-apiserver` service type defaults to `NodePort`. Depending on
your k8s provider it may be beneficial to change this to `LoadBalancer`:

   $ helm install cilium ... \
     --set clustermesh.apiserver.service.type=LoadBalancer \

Additionally, if your load balancer can give you a static IP address, it may be
specified like so:

   $ helm install cilium ... \
     --set clustermesh.apiserver.service.loadBalancerIP=xxx.xxx.xxx.xxx \

## Connect Cilium clusters in to a clustermesh

1. Extract a `cilium-clustermesh` secret from each cluster to be applied in another cluster:

   $ contrib/k8s/k8s-extract-clustermesh-nodeport-secret.sh > cluster1-secret.json

   Repeat this step in all your clusters, storing the outputs into different files.

3. Apply secrets from all other clusters in each of your clusters, e.g., on cluster1:

   $ contrib/k8s/k8s-import-clustermesh-secrets.sh cluster2-secret.json cluster3-secret.json ...

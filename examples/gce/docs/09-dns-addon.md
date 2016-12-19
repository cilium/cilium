# Deploying the Cluster DNS Add-on

In this lab you will deploy the DNS add-on which is required for every Kubernetes cluster. Without the DNS add-on the following things will not work:

* DNS based service discovery
* DNS lookups from containers running in pods

## Cluster DNS Add-on

### Create the `kubedns` service:

```
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/gce/deployments/kubedns-svc.yaml
```

#### Verification

```
kubectl --namespace=kube-system get svc
```
```
NAME                   CLUSTER-IP    EXTERNAL-IP   PORT(S)         AGE
kube-dns               10.32.0.10    <none>        53/UDP,53/TCP   1d
```

### Create the `kubedns` deployment:

```
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/gce/deployments/kubedns-rc.yaml
```

#### Verification

```
kubectl --namespace=kube-system get pods
```
```
NAME                           READY     STATUS    RESTARTS   AGE
kube-dns-v20-965658604-c8g5d   3/3       Running   0          49s
kube-dns-v20-965658604-zwl3g   3/3       Running   0          49s
```

### Create the `kubernetes dashboard` deployment:

```
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/gce/deployments/kubedns-rc.yaml
```

#### Verification

```
kubectl --namespace=kube-system get svc
```
```
NAME                   CLUSTER-IP   EXTERNAL-IP   PORT(S)         AGE
kube-dns               10.32.0.10   <none>        53/UDP,53/TCP   1h
kubernetes-dashboard   10.32.0.65   <none>        80/TCP          1h
```

```
kubectl --namespace=kube-system get pods
```
```
NAME                                    READY     STATUS    RESTARTS   AGE
kube-dns-v20-918099234-nmtj8            3/3       Running   0          1h
kube-dns-v20-918099234-sttqb            3/3       Running   0          1h
kubernetes-dashboard-1566287657-tlr58   1/1       Running   0          1h
```
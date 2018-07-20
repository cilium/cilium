Kubernetes etcd-operator integration (beta)
===========================================

This directory contains all the necessary files to deploy etcd-operator with
Cilium in your development cluster.

Create etcd certificates
------------------------

The first step you need to do is

```
tls/certs/gen-cert.sh <cluster domain>
```
where `<cluster domain>` is the domain the cluster set up in kube-dns.

You can find it by checking the config map of core-dns by running
```
kubectl get ConfigMap --namespace kube-system coredns -o yaml | grep kubernetes
```

or by checking the kube-dns deployment and grepping for 'domain'
```
kubectl get Deployment --namespace kube-system kube-dns -o yaml | grep domain
```

For reference, the cluster domain used in Kubernetes clusters by default is `'cluster.local'`

Deploy generated certificates
-----------------------------

The next step is to deploy the certificates generated on the previous step
in the Kubernetes cluster, this can be achieved by running.

```
tls/deploy-certs.sh
```

Deploy kube-dns and make sure it contains the required label
------------------------------------------------------------

Before running this step, make sure you have kube-dns running and contains
the label `io.cilium.fixed-identity=kube-dns`.

```
kubectl label -n kube-system pod $(kubectl get pods -n kube-system | grep kube-dns | cut -f 1 -d " ") io.cilium.fixed-identity=kube-dns
```

Deploy Kubernetes descriptors for etcd operator as well Cilium
--------------------------------------------------------------

Just simply run `kubectl create -f` on this directory.

```
kubectl create -f ./
```

You might see an error stating:

```
error: unable to recognize "examples/kubernetes/addons/etcd-operator/cilium-etcd-cluster.yaml": no matches for kind "EtcdCluster" in version "etcd.database.coreos.com/v1beta2"
```

this is expected as the `etcd-operator` pod was not running and it did not
create the `etcd.database.coreos.com/v1beta2` CRD. Please wait until the
`etcd-operator` pods are in ready state and then later on try to deploy
`cilium-etcd-cluster.yaml`.

```
$ kubectl get pods -n kube-system
NAME                             READY     STATUS    RESTARTS   AGE
etcd-operator-69b5bfc669-fvm8c   1/1       Running   0          1d
kube-dns-7dcc557ddd-tsqjt        3/3       Running   12         1d
```

```
kubectl create -f ./cilium-etcd-cluster.yaml
```

Wait a couple seconds and everything should be running fine.

```
$ kubectl get pods -n kube-system
NAME                             READY     STATUS    RESTARTS   AGE
cilium-etcd-g2sr9qxdhw           1/1       Running   0          6h
cilium-etcd-ss5jlv4cbq           1/1       Running   0          7h
cilium-etcd-x28h2rkhz7           1/1       Running   0          7h
etcd-operator-69b5bfc669-fvm8c   1/1       Running   0          1d
kube-dns-7dcc557ddd-tsqjt        3/3       Running   12         1d
```

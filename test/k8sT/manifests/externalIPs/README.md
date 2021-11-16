# Update matrix table

`matrix.bash` script should be used by a developer to update the matrix table,
i.e., the `*to_node.go` files in this directory. The developer sets up an
environment with 2 nodes running k8s with kube-proxy and cilium with the
node-port feature disabled, the results of the matrix.bash testing will be the
baseline and the conformity for the tests being executed in ginkgo, where cilium
will run with node-port feature enabled and without kube-proxy.

## Create a k8s cluster with 2 nodes *and* NFS

```bash
NETNEXT=1 NFS=1 NWORKERS=1 K8S=1 ./contrib/vagrant/start.sh
```

the NFS is important because it makes the script to create 2 network interfaces on each VM.

## When both VMs are up and ready ssh in one of them and run:
```bash
kubectl label node k8s1 'cilium.io/ci-node=k8s1'
kubectl label node k8s2 'cilium.io/ci-node=k8s2'
```

## Create the service tests

```bash
kubectl create ns external-ips-test
kubectl apply -f test/k8sT/manifests/externalIPs
```

We now have a 2 externalIPs services exposed in both nodes. We have 3 externalIPs
configured on each service, 2 of those IPs (`192.168.33.11` and `192.168.34.11`)
should belong to k8s1, the 3rd (`192.0.2.233`) represent a externalIP that is
routable in the cluster.

## Once the pods and services are up and running run:

```bash
bash test/k8sT/manifests/externalIPs/matrix.bash -g external-ips-test
```

This will give you an example output of the command that you should use to test.

Then execute the command where you have a valid KUBECONFIG file that points
to the cluster running those 2 nodes:

TODO: provide a way to run the script automatically for a 3rd host.
Execute the same command **without** the `-c` flag in the host that is hosting
both VMs. **Do not forget** to run `sudo ip route add 192.0.2.0/24 via 192.168.34.11` so
you can actually make requests to `k8s1` with the destination IP `192.0.2.233`

Also, **DO NOT FORGET** the remove the route after being done with the test in
the `host`, otherwise the test behavior when running in `k8s1` and `k8s2` might
not be the expected one.

* host - This will simulate the behavior of a client running outside the cluster.

If you want, repeat the previous steps for cilium with node-port feature, for
that run on `k8s1` and `k8s2`:

```bash
sudo service kube-proxy stop && sudo su -c 'iptables-save | grep -v KUBE | iptables-restore'
```

and start cilium with `--enable-node-port --device=enp0s10`

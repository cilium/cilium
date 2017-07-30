## Kubernetes multi node tests

This directory contains the necessary files to setup a 2 node kubernetes
cluster.

The directory structure is composed as follow:

- `cluster/` - files that have the kubernetes configurations
    - `certs/` - certificates used in kubernetes components and in etcd, the
    files are already generated so there's no need to regenerated them again.
    - `cilium/` - cilium daemon sets adjusted to this cluster with a daemon set
    for the loadbalancer mode. The files are generated on the fly based on the
    `*.sed` files present.
    - `cluster-manager.bash` - the script in charge of the certificates,
    kubernetes and cilium files generation. It is also in charge of setting up
    and deploy a fully kubernetes cluster with etcd running. This file has
    several configurable options, like the version of etcd and k8s.
- `tests/` - the directory where the tests should be stored
    - `deployments/` - yaml files to be managed for each runtime test.
    - `ipv4/` - tests that are designed to be ran only in IPv4 mode.
    - `ipv6/` - tests that are designed to be ran only in IPv6 mode.
    - `00-setup-kubedns.sh` - script that makes sure kube-dns is up and running.
    - `xx-test-name.sh` - all tests with this format will be ran in both IPv4
    and IPv6 mode.
- `run-tests.bash` - in charge of running the runtime tests, setting up of the
   IPv6 environment for the cluster, and running of the runtime tests in IPv6.

### Cluster architecture

Running `vagrant up` will start 2 VMs: `k8s1` and
`k8s2`.

#### `k8s1`

`k8s1` will contain the etcd server, kube-apiserver,
kube-controller-manager, kube-scheduler and a kubelet instance. All kubernetes
components are spawned by kubeadm.

All components will be running in containers **except** kubelet and etcd.

This node will have 3 static IPs and 2 interfaces:

`enp0s8`: `192.168.36.11/24` and `fd01::b/16`

`enp0s9`: `192.168.37.11/24`

#### `k8s2`

`k8s2` will only contain a kubelet instance running.

This node will also have the 3 static IPs and 2 interfaces:

`enp0s8`: `192.168.36.12/24` and `fd01::c/16`

`enp0s9`: `192.168.37.12/24`

### Switching between IPv4 and IPv6

After running `vagrant up` kubernetes and etcd will be running with TLS set up.
Note that cilium **will not be set up**.

Kubernetes will be running in IPv4 mode by default, to run with IPv6 mode, after
the machines are set up and running, run:

```
vagrant ssh ${vm} -- -t '/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster/cluster-manager.bash reinstall --ipv6 --yes-delete-all-etcd-data'
vagrant ssh ${vm} -- -t 'sudo cp -R /root/.kube /home/vagrant'
vagrant ssh ${vm} -- -t 'sudo chown vagrant.vagrant -R /home/vagrant/.kube'
```

Where `${vm}` should be replaced with `k8s1` and `k8s2`.

This will reset the kubernetes cluster to it's initial state.

To revert it back to IPv4, run the same commands before without providing the
`--ipv6` option on the first command.

### Deploying cilium

To deploy cilium after kubernetes is set up, simply run:

```
vagrant ssh k8s2 -- -t '/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster/cluster-manager.bash deploy_cilium'
```

This command only needs to be executed in one of the nodes; since Cilium is
deployed as a DaemonSet, Kubernetes will deploy it on each node accordingly.

Cilium will also connect to etcd and kubernetes using TLS.

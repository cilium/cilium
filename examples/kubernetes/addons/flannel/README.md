Cilium integration with Flannel (EXPERIMENTAL)
==============================================

This directory contains the necessary scripts to run Cilium on top of your
Flannel cluster.

If you have your cluster already set up with Flannel will not need to install
Flannel again.

Flannel installation
--------------------

NOTE: If `kubeadm` is used, then pass `--pod-network-cidr=10.244.0.0/16` to
`kubeadm init` to ensure that the `podCIDR` is set.

```bash
kubectl -f ./flannel.yaml
```

Wait all pods to be in ready state before preceding to the next step.

Cilium installation
-------------------

Download Cilium k8s descriptor

```bash
curl https://raw.githubusercontent.com/cilium/cilium/master/examples/kubernetes/1.8/cilium.yaml
```

Edit the ConfigMap in that file with the etcd server that is running in your
cluster and set the option `policy-enforcement-interface` with "cni0".

Also set `policy-enforcement-clean-up` with either `true` or `false`. If you
plan to deploy Cilium and ensure the policy enforcement will always be kept even
if you remove Cilium, then leave the option with `false`. If you plan to test
Cilium in your cluster and remove Cilium once you have finish your tests, by
setting the option with `true` will make sure the Cilium will clean up all BPF
programs generated from the host where Cilium was running.

```yaml
  # Interface to be used when running Cilium on top of a CNI plugin.
  # For flannel, use "cni0"
  policy-enforcement-interface: "cni0"
  # When running Cilium with policy enforcement enabled on top of a CNI plugin
  # the BPF programs will be installed on the network interface specified in
  # 'policy-enforcement-interface' and on all network interfaces belonging to
  # a container. When the Cilium DaemonSet is removed, the BPF programs will
  # be kept in the interfaces unless this option is set to "true".
  policy-enforcement-clean-up: "false"
```

Once you have change the configuration map accordingly, you can deploy Cilium.

Cilium might not come up immediately on all nodes, since flannel only sets up
the bridge network interface that connects containers with the outside world
when the first container is created on that node, Cilium will wait until that
bridge is connected.
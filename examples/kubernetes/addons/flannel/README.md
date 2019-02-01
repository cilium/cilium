Cilium integration with Flannel (EXPERIMENTAL)
==============================================

This directory contains the necessary scripts to run Cilium on top of your
Flannel cluster.

If you have your cluster already set up with Flannel you will not need to
install Flannel again.

This Cilium integration with Flannel was performed with Flannel 0.10.0 and
Kubernetes >= 1.9. If you find any issues with previous Flannel versions please
feel free to reach us out to help you.

Flannel installation
--------------------

NOTE: If `kubeadm` is used, then pass `--pod-network-cidr=10.244.0.0/16` to
`kubeadm init` to ensure that the `podCIDR` is set.

```bash
kubectl -f https://raw.githubusercontent.com/cilium/cilium/v1.4.0/examples/kubernetes/addons/flannel/flannel.yaml
```

Wait until all pods to be in ready state before preceding to the next step.

Cilium installation
-------------------

Download Cilium k8s descriptor

```bash
curl https://raw.githubusercontent.com/cilium/cilium/v1.4.0/examples/kubernetes/1.9/cilium.yaml
```

Edit the ConfigMap in that file and set the option `flannel-master-device` with "cni0".

Also set `flannel-uninstall-on-exit` with either `true` or `false`. If you
plan to deploy Cilium and ensure the policy enforcement will always be kept even
if you remove Cilium, then leave the option with `false`. If you plan to test
Cilium in your cluster and remove Cilium once you have finish your tests, by
setting the option with `true` will make sure the Cilium will clean up all BPF
programs generated from the host where Cilium was running.

*Optional step:*
If your cluster has already pods being managed by Flannel, there is also
an option available that allows Cilium to start managing those pods without
requiring to restart them. To enable this functionality you need to set the
value `flannel-manage-existing-containers` to `true` **and** modify
the `hostPID` value in the Cilium DaemonSet to `true`. Running
Cilium with `hostPID` is required because Cilium needs to access the network
namespaces of those already running pods in order to derive the MAC address and
IP address.

```yaml
  # Interface to be used when running Cilium on top of a CNI plugin.
  # For flannel, use "cni0"
  flannel-master-device: "cni0"
  # When running Cilium with policy enforcement enabled on top of a CNI plugin
  # the BPF programs will be installed on the network interface specified in
  # 'flannel-master-device' and on all network interfaces belonging to
  # a container. When the Cilium DaemonSet is removed, the BPF programs will
  # be kept in the interfaces unless this option is set to "true".
  flannel-uninstall-on-exit: "false"
  # Installs a BPF program to allow for policy enforcement in already running
  # containers managed by Flannel.
  # NOTE: This requires Cilium DaemonSet to be running in the hostPID.
  # To run in this mode in Kubernetes change the value of the hostPID from
  # false to true. Can be found under the path `spec.spec.hostPID`
  flannel-manage-existing-containers: "false"
```

Once you have change the configuration map accordingly, you can deploy Cilium.

```
kubectl create -f ./cilium.yaml
```

Cilium might not come up immediately on all nodes, since flannel only sets up
the bridge network interface that connects containers with the outside world
when the first container is created on that node, Cilium will wait until that
bridge is connected.

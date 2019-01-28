node-init DaemonSet
===================

The node-init DaemonSet prepares a node to run Cilium, it will:

 * Install a systemd service to mount the BPF filesystem when the node boots
   up. The service is called `sys-fs-bpf.mount` and installed in
   `/etc/systemd/system/` or `/lib/systemd/system/` depending on which
   directory exists.

 * Change the kubelet configuration to include `--network-plugin=cni
   --cni-bin-dir=/home/kubernetes/bin` and restart kubelet.

 * Write a Cilium CNI configuration file to `/etc/cni/net.d/04-cilium-cni.conf`

Requirements
------------

 * When using node-init, the Cilium DaemonSet must be instructed to write the
   `cilium-cni` binary into `/home/kubernetes/bin`

# Installation instructions for libvirt

The file `contrib/libvirt.xml` contains an example configuration for an
IPv4 and IPv6 network with the name `cilium-test`. The `Vagrantfile` in
the project root directoy assumes that a `cilium-test` network exists.

```
virsh net-define contrib/libvirt.xml
virsh net-start cilium-test
virsh net-autostart cilium-test
```

# ptp plugin

## Overview
The ptp plugin creates a point-to-point link between a container and the host by using a veth device.
One end of the veth pair is placed inside a container and the other end resides on the host.
The host-local IPAM plugin can be used to allocate an IP address to the container.
The traffic of the container interface will be routed through the interface of the host.

## Example network configuration

```
{
	"name": "mynet",
	"type": "ptp",
	"ipam": {
		"type": "host-local",
		"subnet": "10.1.1.0/24"
	},
	"dns": {
		"nameservers": [ "10.1.1.1", "8.8.8.8" ]
	}
}
```

## Network configuration reference

* `name` (string, required): the name of the network
* `type` (string, required): "ptp"
* `ipMasq` (boolean, optional): set up IP Masquerade on the host for traffic originating from this network and destined outside of it. Defaults to false.
* `mtu` (integer, optional): explicitly set MTU to the specified value. Defaults to value chosen by the kernel.
* `ipam` (dictionary, required): IPAM configuration to be used for this network.
* `dns` (dictionary, optional): DNS information to return as described in the [Result](/SPEC.md#result).

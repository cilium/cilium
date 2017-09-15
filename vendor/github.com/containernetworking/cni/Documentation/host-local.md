# host-local IP address management plugin

host-local IPAM allocates IPv4 and IPv6 addresses out of a specified address range. Optionally,
it can include a DNS configuration from a `resolv.conf` file on the host.

## Overview

host-local IPAM plugin allocates IPv4 addresses out of a specified address range.
It stores the state locally on the host filesystem, therefore ensuring uniqueness of IP addresses on a single host.

## Example configurations

IPv4:
```json
{
	"ipam": {
		"type": "host-local",
		"subnet": "10.10.0.0/16",
		"rangeStart": "10.10.1.20",
		"rangeEnd": "10.10.3.50",
		"gateway": "10.10.0.254",
		"routes": [
			{ "dst": "0.0.0.0/0" },
			{ "dst": "192.168.0.0/16", "gw": "10.10.5.1" }
		],
		"dataDir": "/var/my-orchestrator/container-ipam-state"
	}
}
```

IPv6:
```json
{
  "ipam": {
		"type": "host-local",
		"subnet": "3ffe:ffff:0:01ff::/64",
		"rangeStart": "3ffe:ffff:0:01ff::0010",
		"rangeEnd": "3ffe:ffff:0:01ff::0020",
		"routes": [
			{ "dst": "3ffe:ffff:0:01ff::1/64" }
		],
		"resolvConf": "/etc/resolv.conf"
	}
}
```

We can test it out on the command-line:

```bash
$ export CNI_COMMAND=ADD
$ export CNI_CONTAINERID=f81d4fae-7dec-11d0-a765-00a0c91e6bf6
$ echo '{ "name": "default", "ipam": { "type": "host-local", "subnet": "203.0.113.0/24" } }' | ./host-local
```

```json
{
    "ip4": {
        "ip": "203.0.113.1/24"
    }
}
```

## Network configuration reference

* `type` (string, required): "host-local".
* `subnet` (string, required): CIDR block to allocate out of.
* `rangeStart` (string, optional): IP inside of "subnet" from which to start allocating addresses. Defaults to ".2" IP inside of the "subnet" block.
* `rangeEnd` (string, optional): IP inside of "subnet" with which to end allocating addresses. Defaults to ".254" IP inside of the "subnet" block.
* `gateway` (string, optional): IP inside of "subnet" to designate as the gateway. Defaults to ".1" IP inside of the "subnet" block.
* `routes` (string, optional): list of routes to add to the container namespace. Each route is a dictionary with "dst" and optional "gw" fields. If "gw" is omitted, value of "gateway" will be used.
* `resolvConf` (string, optional): Path to a `resolv.conf` on the host to parse and return as the DNS configuration
* `dataDir` (string, optional): Path to a directory to use for maintaining state, e.g. which IPs have been allocated to which containers


## Supported arguments
The following [CNI_ARGS](https://github.com/containernetworking/cni/blob/master/SPEC.md#parameters) are supported:

* `ip`: request a specific IP address from the subnet. If it's not available, the plugin will exit with an error

## Files

Allocated IP addresses are stored as files in `/var/lib/cni/networks/$NETWORK_NAME`.  The prefix can be customized with the `dataDir` option listed above.

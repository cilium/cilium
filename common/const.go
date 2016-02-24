package common

import "net"

const (
	PluginPath          = "/run/docker/plugins/"
	DriverSock          = PluginPath + "cilium.sock"
	CiliumPath          = "/var/run/cilium/"
	CiliumSock          = CiliumPath + "cilium.sock"
	DefaultContainerMAC = "AA:BB:CC:DD:EE:FF"
	BPFMap              = "/sys/fs/bpf/tc/globals/cilium_lxc"
	EncapDevice         = "cilium_vxlan"

	OperationalPath   = "cilium-net/operational"
	LastFreeIDKeyPath = OperationalPath + "/LastUUID"
	LabelsKeyPath     = OperationalPath + "/SHA256SUMLabels/"
	IDKeyPath         = OperationalPath + "/ID/"
	MaxSetOfLabels    = 0xFFFF
)

var (
	// Default addressing schema
	//
	// cluster:		    beef:beef:beef:beef::/64
	// loadbalancer:	beef:beef:beef:beef:<lb>::/80
	// node:		    beef:beef:beef:beef:<lb>:<node>:<node>:/112
	// lxc:			    beef:beef:beef:beef:<lb>:<node>:<node>:<lxc>/128
	ClusterIPv6Mask      = net.CIDRMask(64, 128)
	LoadBalancerIPv6Mask = net.CIDRMask(80, 128)
	NodeIPv6Mask         = net.CIDRMask(112, 128)
	ContainerIPv6Mask    = net.CIDRMask(128, 128)
)

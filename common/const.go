package common

import (
	"net"
)

const (
	// Cilium constants

	// Version number.
	Version = "0.0.1"
	// PluginPath is the docker plugins directory where docker plugin is present.
	PluginPath = "/run/docker/plugins/"
	// DriverSock is the cilium socket for the communication between docker and cilium.
	DriverSock = PluginPath + "cilium.sock"
	// CiliumPath is the path where cilium operational files are running.
	CiliumPath   = "/var/run/cilium/"
	CiliumUIPath = CiliumPath + "static/"
	CiliumLibDir = "/usr/lib/cilium"
	// CiliumSock is the cilium socket for the communication between the daemon and cilium client.
	CiliumSock = CiliumPath + "cilium.sock"
	// DefaultContainerMAC represents a dummy MAC address for the containers.
	DefaultContainerMAC = "AA:BB:CC:DD:EE:FF"
	// BPFMap is the file that contains the BPF Map for the host.
	BPFMapRoot    = "/sys/fs/bpf"
	BPFCiliumMaps = BPFMapRoot + "/tc/globals/"
	BPFMap        = BPFCiliumMaps + "cilium_lxc"
	// PolicyMapPath is the base path for the cilium policy for each local container.
	PolicyMapPath = BPFCiliumMaps + "cilium_policy_"
	BPFMapCT      = BPFCiliumMaps + "cilium_ct_"
	// RFC3339Milli is the RFC3339 with milliseconds for the default timestamp format
	// log files.
	RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"
	// DisablePolicyEnforcement represent the C constant to disable policy
	// enforcement.
	DisablePolicyEnforcement = "DISABLE_POLICY_ENFORCEMENT"
	// EnableNAT46 represent the C constant to enable nat46 mode.
	EnableNAT46 = "ENABLE_NAT46"
	// Enable drop notifications
	EnableDropNotify = "DROP_NOTIFY"

	// Consul dedicated constants

	// OperationalPath is the base path to store the operational details in consul.
	OperationalPath = "cilium-net/operational"
	// LastFreeIDKeyPath is the path where the Last free UUID is stored in consul.
	LastFreeIDKeyPath = OperationalPath + "/LastUUID"
	// LabelsKeyPath is the base path where labels are stored in consul.
	LabelsKeyPath = OperationalPath + "/SHA256SUMLabels/"
	// IDKeyPath is the base path where the IDs are stored in consul.
	IDKeyPath = OperationalPath + "/ID/"
	// MaxSetOfLabels is maximum number of set of labels that can be stored in consul.
	MaxSetOfLabels = uint32(0xFFFF)
	// FirstFreeID is the first ID for which the labels should be assigned.
	FirstFreeID = uint32(256)
	// SecCtxFromHost represents reserved security context IDs reserved for special
	// purposes.
	SecCtxFromHost = 1

	// Networking dedicated constants

	// DefaultIPv6Prefix is the default IPv6 address assigned to the cilium interface.
	DefaultIPv6Prefix = "beef::"
	// DefaultIPv4Prefix is the IPv6 prefix used to map IPv4 addresses.
	DefaultIPv4Prefix = "dead::"
	// DefaultIPv4Range is the CIDR used for 6to4 communications.
	DefaultIPv4Range = `10.%d.0.0/16`
	// DefaultIPv4Mask is the default mask for the CIDR used for 6to4 communications.
	DefaultIPv4Mask = 16

	// Miscellaneous dedicated constants

	// GlobalLabelPrefix is the default root path for the policy.
	GlobalLabelPrefix = "io.cilium"
	// CiliumLabelSource is the default label source for the labels read from containers.
	CiliumLabelSource = "cilium"
	// K8sLabelSource is the default label source for the labels read from kubernetes.
	K8sLabelSource = "k8s"
	// K8sAnnotationName is the annotation name used for the cilium policy name in the
	// kubernetes network policy.
	K8sAnnotationName = "io.cilium.name"
	// K8sPodNamespaceLabel is the label used in kubernetes containers to specify
	// which namespace they belong to.
	K8sPodNamespaceLabel = "io.kubernetes.pod.namespace"
	// K8sAnnotationParentName is the annotation name used for the cilium policy
	// parent name in the kubernetes network policy.
	K8sAnnotationParentName = "io.cilium.parent"
	// Label source for reserved types
	ReservedLabelSource = "reserved"
	// EndpointsPerHost is the maximum number of endpoints allowed per host. It should
	// represent the same number of IPv6 addresses supported on each node.
	EndpointsPerHost = 0xFFFF
	// GroupFilePath is the unix group file path.
	GroupFilePath = "/etc/group"
	// CiliumGroupName is the cilium's unix group name.
	CiliumGroupName = "cilium"

	// Endpoint prefixes

	// CiliumPrefix is used to distinguish cilium IDs between different ID types.
	CiliumPrefix = "cilium://"
	// DockerPrefix is used to distinguish docker ID between different ID types.
	DockerPrefix = "docker://"
	// DockerEPPrefix is used to distinguish docker endpoints ID between different ID
	// types.
	DockerEPPrefix = "dockerEPID://"
	// CHeaderFileName is the name of the C header file for BPF programs for a
	// particular endpoint.
	CHeaderFileName = "lxc_config.h"
	// CiliumCHeaderPrefix is the prefix using when printing/writing an endpoint in a
	// base64 form.
	CiliumCHeaderPrefix = "CILIUM_BASE64_"
)

var (
	// Default addressing schema
	//
	// cluster:		    beef:beef:beef:beef::/64
	// loadbalancer:            beef:beef:beef:beef:<lb>::/80
	// node:		    beef:beef:beef:beef:<lb>:<node>:<node>:/112
	// lxc:			    beef:beef:beef:beef:<lb>:<node>:<node>:<lxc>/128

	// ClusterIPv6Mask represents the CIDR Mask for the cilium cluster.
	ClusterIPv6Mask = net.CIDRMask(64, 128)
	// LoadBalancerIPv6Mask represents the CIDR Mask for the cilium load balancer.
	LoadBalancerIPv6Mask = net.CIDRMask(80, 128)
	// NodeIPv6Mask represents the CIDR Mask for the cilium node.
	NodeIPv6Mask = net.CIDRMask(112, 128)
	// ContainerIPv6Mask represents the CIDR Mask for the cilium endpoint/container.
	ContainerIPv6Mask = net.CIDRMask(128, 128)
)

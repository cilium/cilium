package common

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
	BPFMapCT6     = BPFCiliumMaps + "cilium_ct6_"
	BPFMapCT4     = BPFCiliumMaps + "cilium_ct4_"
	// RFC3339Milli is the RFC3339 with milliseconds for the default timestamp format
	// log files.
	RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"

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
	// Label used to represent the reserved source
	ReservedLabelKey = GlobalLabelPrefix + "." + ReservedLabelSource
	// EndpointsPerHost is the maximum number of endpoints allowed per host. It should
	// represent the same number of IPv6 addresses supported on each node.
	EndpointsPerHost = 0xFFFF
	// GroupFilePath is the unix group file path.
	GroupFilePath = "/etc/group"
	// CiliumGroupName is the cilium's unix group name.
	CiliumGroupName = "cilium"

	// CHeaderFileName is the name of the C header file for BPF programs for a
	// particular endpoint.
	CHeaderFileName = "lxc_config.h"
	// Name of the header file used for bpf_netdev.c and bpf_overlay.c
	NetdevHeaderFileName = "netdev_config.h"
	// CiliumCHeaderPrefix is the prefix using when printing/writing an endpoint in a
	// base64 form.
	CiliumCHeaderPrefix = "CILIUM_BASE64_"
)

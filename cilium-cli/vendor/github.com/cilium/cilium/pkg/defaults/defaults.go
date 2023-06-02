// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

import (
	"time"
)

const (
	// AgentHealthPort is the default value for option.AgentHealthPort
	AgentHealthPort = 9879

	// ClusterHealthPort is the default value for option.ClusterHealthPort
	ClusterHealthPort = 4240

	// ClusterMeshHealthPort is the default value for option.ClusterMeshHealthPort
	ClusterMeshHealthPort = 80

	// GopsPortAgent is the default value for option.GopsPort in the agent
	GopsPortAgent = 9890

	// GopsPortOperator is the default value for option.GopsPort in the operator
	GopsPortOperator = 9891

	// GopsPortApiserver is the default value for option.GopsPort in the apiserver
	GopsPortApiserver = 9892

	// IPv6ClusterAllocCIDR is the default value for option.IPv6ClusterAllocCIDR
	IPv6ClusterAllocCIDR = IPv6ClusterAllocCIDRBase + "/64"

	// IPv6ClusterAllocCIDRBase is the default base for IPv6ClusterAllocCIDR
	IPv6ClusterAllocCIDRBase = "f00d::"

	// IPv6NAT46x64CIDR is the default prefix for NAT46x64 gateway
	IPv6NAT46x64CIDR = IPv6NAT46x64CIDRBase + "/96"

	// IPv6NAT46x64CIDRBase is the default base for IPv6NAT46x64CIDR
	IPv6NAT46x64CIDRBase = "64:ff9b::"

	// RuntimePath is the default path to the runtime directory
	RuntimePath = "/var/run/cilium"

	// RuntimePathRights are the default access rights of the RuntimePath directory
	RuntimePathRights = 0775

	// StateDirRights are the default access rights of the state directory
	StateDirRights = 0770

	//StateDir is the default path for the state directory relative to RuntimePath
	StateDir = "state"

	// TemplatesDir is the default path for the compiled template objects relative to StateDir
	TemplatesDir = "templates"

	// TemplatePath is the default path for a symlink to a template relative to StateDir/<EPID>
	TemplatePath = "template.o"

	// BpfDir is the default path for template files relative to LibDir
	BpfDir = "bpf"

	// LibraryPath is the default path to the cilium libraries directory
	LibraryPath = "/var/lib/cilium"

	// SockPath is the path to the UNIX domain socket exposing the API to clients locally
	SockPath = RuntimePath + "/cilium.sock"

	// SockPathEnv is the environment variable to overwrite SockPath
	SockPathEnv = "CILIUM_SOCK"

	// HubbleSockPath is the path to the UNIX domain socket exposing the Hubble
	// API to clients locally.
	HubbleSockPath = RuntimePath + "/hubble.sock"

	// HubbleSockPathEnv is the environment variable to overwrite
	// HubbleSockPath.
	HubbleSockPathEnv = "HUBBLE_SOCK"

	// HubbleRecorderStoragePath specifies the directory in which pcap files
	// created via the Hubble Recorder API are stored
	HubbleRecorderStoragePath = RuntimePath + "/pcaps"

	// HubbleRecorderSinkQueueSize is the queue size for each recorder sink
	HubbleRecorderSinkQueueSize = 1024

	// MonitorSockPath1_2 is the path to the UNIX domain socket used to
	// distribute BPF and agent events to listeners.
	// This is the 1.2 protocol version.
	MonitorSockPath1_2 = RuntimePath + "/monitor1_2.sock"

	// PidFilePath is the path to the pid file for the agent.
	PidFilePath = RuntimePath + "/cilium.pid"

	// DeletionQueueDir is the directory used for the CNI plugin to queue deletion requests
	// if the agent is down
	DeleteQueueDir = RuntimePath + "/deleteQueue"

	// DeleteQueueLockfile is the file used to synchronize access of the queue directory between
	// the agent and the CNI plugin processes
	DeleteQueueLockfile = DeleteQueueDir + "/lockfile"

	// EnableHostIPRestore controls whether the host IP should be restored
	// from previous state automatically
	EnableHostIPRestore = true

	// BPFFSRoot is the default path where BPFFS should be mounted
	BPFFSRoot = "/sys/fs/bpf"

	// BPFFSRootFallback is the path which is used when /sys/fs/bpf has
	// a mount, but with the other filesystem than BPFFS.
	BPFFSRootFallback = "/run/cilium/bpffs"

	// TCGlobalsPath is the default prefix for all BPF maps.
	TCGlobalsPath = "tc/globals"

	// DefaultCgroupRoot is the default path where cilium cgroup2 should be mounted
	DefaultCgroupRoot = "/run/cilium/cgroupv2"

	// DNSMaxIPsPerRestoredRule defines the maximum number of IPs to maintain
	// for each FQDN selector in endpoint's restored DNS rules.
	DNSMaxIPsPerRestoredRule = 1000

	// FFQDNRegexCompileLRUSize defines the maximum size for the FQDN regex
	// compilation LRU used by the DNS proxy and policy validation.
	FQDNRegexCompileLRUSize = 1024

	// ToFQDNsMinTTL is the default lower bound for TTLs used with ToFQDNs rules.
	// This is used in DaemonConfig.Populate
	ToFQDNsMinTTL = 0

	// ToFQDNsMaxIPsPerHost defines the maximum number of IPs to maintain
	// for each FQDN name in an endpoint's FQDN cache
	ToFQDNsMaxIPsPerHost = 50

	// ToFQDNsMaxDeferredConnectionDeletes Maximum number of IPs to retain for
	// expired DNS lookups with still-active connections
	ToFQDNsMaxDeferredConnectionDeletes = 10000

	// ToFQDNsIdleConnectionGracePeriod Time during which idle but
	// previously active connections with expired DNS lookups are
	// still considered alive
	ToFQDNsIdleConnectionGracePeriod = 0 * time.Second

	// FQDNProxyResponseMaxDelay The maximum time the DNS proxy holds an allowed
	// DNS response before sending it along. Responses are sent as soon as the
	//datapath is updated with the new IP information.
	FQDNProxyResponseMaxDelay = 100 * time.Millisecond

	// ToFQDNsPreCache is a path to a file with DNS cache data to insert into the
	// global cache on startup.
	// The file is not re-read after agent start.
	ToFQDNsPreCache = ""

	// ToFQDNsEnableDNSCompression allows the DNS proxy to compress responses to
	// endpoints that are larger than 512 Bytes or the EDNS0 option, if present.
	ToFQDNsEnableDNSCompression = true

	// IdentityChangeGracePeriod is the default value for
	// option.IdentityChangeGracePeriod
	IdentityChangeGracePeriod = 5 * time.Second

	// IdentityRestoreGracePeriod is the default value for
	// option.IdentityRestoreGracePeriod
	IdentityRestoreGracePeriod = 10 * time.Minute

	// ExecTimeout is a timeout for executing commands.
	ExecTimeout = 300 * time.Second

	// StatusCollectorInterval is the interval between a probe invocations
	StatusCollectorInterval = 5 * time.Second

	// StatusCollectorWarningThreshold is the duration after which a probe
	// is declared as stale
	StatusCollectorWarningThreshold = 15 * time.Second

	// StatusCollectorFailureThreshold is the duration after which a probe
	// is considered failed
	StatusCollectorFailureThreshold = 1 * time.Minute

	// EnableIPv4 is the default value for IPv4 enablement
	EnableIPv4 = true

	// EnableIPv6 is the default value for IPv6 enablement
	EnableIPv6 = true

	// EnableIPv6NDP is the default value for IPv6 NDP support enablement
	EnableIPv6NDP = false

	// EnableSRv6 is the default value for the SRv6 support enablement.
	EnableSRv6 = false

	// SRv6EncapMode is the encapsulation mode for SRv6.
	SRv6EncapMode = "reduced"

	// EnableSCTP is the default value for SCTP support enablement
	EnableSCTP = false

	// EnableL7Proxy is the default value for L7 proxy enablement
	EnableL7Proxy = true

	// EnvoyConfigTimeout determines how long to wait Envoy to N/ACK resources
	EnvoyConfigTimeout = 2 * time.Minute

	// EnableHostLegacyRouting is the default value for using the old routing path via stack.
	EnableHostLegacyRouting = false

	// EnableExternalIPs is the default value for k8s service with externalIPs feature.
	EnableExternalIPs = true

	// K8sEnableEndpointSlice is the default value for k8s EndpointSlice feature.
	K8sEnableEndpointSlice = true

	// PreAllocateMaps is the default value for BPF map preallocation
	PreAllocateMaps = true

	// EnableIPSec is the default value for IPSec enablement
	EnableIPSec = false

	// IPsecKeyRotationDuration is the time to wait before removing old keys when
	// the IPsec key is changing.
	IPsecKeyRotationDuration = 5 * time.Minute

	// EncryptNode enables encrypting traffic from host networking applications
	// which are not part of Cilium manged pods.
	EncryptNode = false

	// NodeEncryptionOptOutLabels contains the label selectors for nodes opting out of
	// node-to-node encryption
	NodeEncryptionOptOutLabels = "node-role.kubernetes.io/control-plane"

	// MonitorQueueSizePerCPU is the default value for the monitor queue
	// size per CPU
	MonitorQueueSizePerCPU = 1024

	// MonitorQueueSizePerCPUMaximum is the maximum value for the monitor
	// queue size when derived from the number of CPUs
	MonitorQueueSizePerCPUMaximum = 16384

	// NodeInitTimeout is the time the agent is waiting until giving up to
	// initialize the local node with the kvstore
	NodeInitTimeout = 15 * time.Minute

	// ClientConnectTimeout is the time the cilium-agent client is
	// (optionally) waiting before returning an error.
	ClientConnectTimeout = 30 * time.Second

	// DatapathMode is the default value for the datapath mode.
	DatapathMode = "veth"

	// EnableBPFTProxy is the default value for EnableBPFTProxy
	EnableBPFTProxy = false

	// EnableXTSocketFallback is the default value for EnableXTSocketFallback
	EnableXTSocketFallback = true

	// EnableLocalNodeRoute default value for EnableLocalNodeRoute
	EnableLocalNodeRoute = true

	// EnableAutoDirectRouting is the default value for EnableAutoDirectRouting
	EnableAutoDirectRouting = false

	// EnableHealthChecking is the default value for EnableHealthChecking
	EnableHealthChecking = true

	// EnableEndpointHealthChecking is the default value for
	// EnableEndpointHealthChecking
	EnableEndpointHealthChecking = true

	// EnableHealthCheckNodePort is the default value for
	// EnableHealthCheckNodePort
	EnableHealthCheckNodePort = true

	// AlignCheckerName is the BPF object name for the alignchecker.
	AlignCheckerName = "bpf_alignchecker.o"

	// KVstorePeriodicSync is the default kvstore periodic sync interval
	KVstorePeriodicSync = 5 * time.Minute

	// KVstoreConnectivityTimeout is the timeout when performing kvstore operations
	KVstoreConnectivityTimeout = 2 * time.Minute

	// KVStoreStaleLockTimeout is the timeout for when a lock is held for
	// a kvstore path for too long.
	KVStoreStaleLockTimeout = 30 * time.Second

	// IPAllocationTimeout is the timeout when allocating CIDRs
	IPAllocationTimeout = 2 * time.Minute

	// PolicyQueueSize is the default queue size for policy-related events.
	PolicyQueueSize = 100

	// KVstoreQPS is default rate limit for kv store operations
	KVstoreQPS = 20

	// EndpointQueueSize is the default queue size for an endpoint.
	EndpointQueueSize = 25

	// K8sSyncTimeout specifies the default time to wait after the last event
	// of a Kubernetes resource type before timing out while waiting for synchronization.
	K8sSyncTimeout = 3 * time.Minute

	// AllocatorListTimeout specifies the standard time to allow for listing
	// initial allocator state from kvstore before exiting.
	AllocatorListTimeout = 3 * time.Minute

	// K8sWatcherEndpointSelector specifies the k8s endpoints that Cilium
	// should watch for.
	K8sWatcherEndpointSelector = "metadata.name!=kube-scheduler,metadata.name!=kube-controller-manager,metadata.name!=etcd-operator,metadata.name!=gcp-controller-manager"

	// ConntrackGCMaxLRUInterval is the maximum conntrack GC interval when using LRU maps
	ConntrackGCMaxLRUInterval = 12 * time.Hour

	// ConntrackGCMinInterval is the minimum conntrack GC interval
	ConntrackGCMinInterval = 10 * time.Second

	// ConntrackGCStartingInterval is the default starting interval for
	// connection tracking garbage collection
	ConntrackGCStartingInterval = 5 * time.Minute

	// K8sEventHandover enables use of the kvstore to optimize Kubernetes
	// event handling by listening for k8s events in the operator and
	// mirroring it into the kvstore for reduced overhead in large
	// clusters.
	K8sEventHandover = false

	// LoopbackIPv4 is the default address for service loopback
	LoopbackIPv4 = "169.254.42.1"

	// EnableEndpointRoutes is the value for option.EnableEndpointRoutes.
	// It is disabled by default for backwards compatibility.
	EnableEndpointRoutes = false

	// AnnotateK8sNode is the default value for option.AnnotateK8sNode. It is
	// disabled by default to annotate kubernetes node and can be enabled using
	// the provided option.
	AnnotateK8sNode = false

	// MonitorBufferPages is the default number of pages to use for the
	// ring buffer interacting with the kernel
	MonitorBufferPages = 64

	// NodeDeleteDelay is the delay before an unreliable node delete is
	// handled. During this delay, the node can re-appear and the delete
	// event is ignored.
	NodeDeleteDelay = 30 * time.Second

	// KVstoreLeaseTTL is the time-to-live of the kvstore lease.
	KVstoreLeaseTTL = 15 * time.Minute

	// KVstoreMaxConsecutiveQuorumErrors is the maximum number of acceptable
	// kvstore consecutive quorum errors before the agent assumes permanent failure
	KVstoreMaxConsecutiveQuorumErrors = 2

	// KVstoreKeepAliveIntervalFactor is the factor to calculate the interval
	// from KVstoreLeaseTTL in which KVstore lease is being renewed.
	KVstoreKeepAliveIntervalFactor = 3

	// LockLeaseTTL is the time-to-live of the lease dedicated for locks of Kvstore.
	LockLeaseTTL = 25 * time.Second

	// KVstoreLeaseMaxTTL is the upper bound for KVStore lease TTL value.
	// It is calculated as Min(int64 positive max, etcd MaxLeaseTTL, consul MaxLeaseTTL)
	KVstoreLeaseMaxTTL = 86400 * time.Second

	// IPAMPreAllocation is the default value for
	// CiliumNode.Spec.IPAM.PreAllocate if no value is set
	IPAMPreAllocation = 8

	// IPAMMultiPoolPreAllocation is the default value for multi-pool IPAM
	// pre-allocations
	IPAMMultiPoolPreAllocation = "default=8"

	// ENIFirstInterfaceIndex is the default value for
	// CiliumNode.Spec.ENI.FirstInterfaceIndex if no value is set.
	ENIFirstInterfaceIndex = 0

	// UseENIPrimaryAddress is the default value for
	// CiliumNode.Spec.ENI.UsePrimaryAddress if no value is set.
	UseENIPrimaryAddress = false

	// ENIDisableNodeLevelPD  is the default value for
	// CiliumNode.Spec.ENI.DisablePrefixDelegation if no value is set.
	ENIDisableNodeLevelPD = false

	// ENIGarbageCollectionTagManagedName is part of the ENIGarbageCollectionTags default tag set
	ENIGarbageCollectionTagManagedName = "io.cilium/cilium-managed"

	// ENIGarbageCollectionTagManagedValue is part of the ENIGarbageCollectionTags default tag set
	ENIGarbageCollectionTagManagedValue = "true"

	// ENIGarbageCollectionTagClusterName is part of the ENIGarbageCollectionTags default tag set
	ENIGarbageCollectionTagClusterName = "io.cilium/cluster-name"

	// ENIGarbageCollectionTagClusterValue is part of the ENIGarbageCollectionTags default tag set
	ENIGarbageCollectionTagClusterValue = ClusterName

	// ENIGarbageCollectionInterval is the default interval for the ENIGarbageCollectionInterval operator flag
	ENIGarbageCollectionInterval = 5 * time.Minute

	// ENIGarbageCollectionMaxPerInterval is the maximum number of ENIs which might be garbage collected
	// per GC interval
	ENIGarbageCollectionMaxPerInterval = 25

	// ParallelAllocWorkers is the default max number of parallel workers doing allocation in the operator
	ParallelAllocWorkers = 50

	// IPAMAPIBurst is the default burst value when rate limiting access to external APIs
	IPAMAPIBurst = 20

	// IPAMAPIQPSLimit is the default QPS limit when rate limiting access to external APIs
	IPAMAPIQPSLimit = 4.0

	// IPAMPodCIDRAllocationThreshold is the default value for
	// CiliumNode.Spec.IPAM.PodCIDRAllocationThreshold if no value is set
	// Defaults to 8, which is similar to IPAMPreAllocation
	IPAMPodCIDRAllocationThreshold = 8

	// IPAMPodCIDRReleaseThreshold is the default value for
	// CiliumNode.Spec.IPAM.PodCIDRReleaseThreshold if no value is set
	// Defaults to 16, which is 2x the allocation threshold to avoid flapping
	IPAMPodCIDRReleaseThreshold = 16

	// AutoCreateCiliumNodeResource enables automatic creation of a
	// CiliumNode resource for the local node
	AutoCreateCiliumNodeResource = true

	// PolicyTriggerInterval is default amount of time between triggers of
	// policy updates are invoked.
	PolicyTriggerInterval = 1 * time.Second

	// K8sClientQPSLimit is the default qps for the k8s client. It is set to 0 because the the k8s client
	// has its own default.
	K8sClientQPSLimit float32 = 0.0

	// K8sClientBurst is the default burst for the k8s client. It is set to 0 because the the k8s client
	// has its own default.
	K8sClientBurst = 0

	// K8sServiceCacheSize is the default value for option.K8sServiceCacheSize
	// which denotes the value of Cilium's K8s service cache size.
	K8sServiceCacheSize = 128

	// AllowICMPFragNeeded is the default value for option.AllowICMPFragNeeded flag.
	// It is enabled by default and directs that the ICMP Fragmentation needed type
	// packets are allowed to enable TCP Path MTU.
	AllowICMPFragNeeded = true

	// RestoreV4Addr is used as match for cilium_host v4 address
	RestoreV4Addr = "cilium.v4.internal.raw "

	// RestoreV6Addr is used as match for cilium_host v6 (router) address
	RestoreV6Addr = "cilium.v6.internal.raw "

	// EnableWellKnownIdentities is enabled by default as this is the
	// original behavior. New default Helm templates will disable this.
	EnableWellKnownIdentities = true

	// CertsDirectory is the default directory used to find certificates
	// specified in the L7 policies.
	CertsDirectory = RuntimePath + "/certs"

	// EnableRemoteNodeIdentity is the default value for option.EnableRemoteNodeIdentity
	EnableRemoteNodeIdentity = true

	// IPAMExpiration is the timeout after which an IP subject to expiratio
	// is being released again if no endpoint is being created in time.
	IPAMExpiration = 10 * time.Minute

	// EnableIPv4FragmentsTracking enables IPv4 fragments tracking for
	// L4-based lookups
	EnableIPv4FragmentsTracking = true

	// FragmentsMapEntries is the default number of entries allowed in an
	// the map used to track datagram fragments.
	FragmentsMapEntries = 8192

	// K8sEnableAPIDiscovery defines whether Kubernetes API groups and
	// resources should be probed using the discovery API
	K8sEnableAPIDiscovery = false

	// EnableIdentityMark enables setting identity in mark field of packet
	// for local traffic
	EnableIdentityMark = true

	// EnableHighScaleIPcache enables the special ipcache mode for high scale
	// clusters. The ipcache content will be reduced to the strict minimum and
	// traffic will be encapsulated to carry security identities.
	EnableHighScaleIPcache = false

	// K8sEnableLeasesFallbackDiscovery enables k8s to fallback to API probing to check
	// for the support of Leases in Kubernetes when there is an error in discovering
	// API groups using Discovery API.
	K8sEnableLeasesFallbackDiscovery = false

	// KubeProxyReplacementHealthzBindAddr is the default kubeproxyReplacement healthz server bind addr
	KubeProxyReplacementHealthzBindAddr = ""

	// InstallNoConntrackRules instructs Cilium to install Iptables rules to skip netfilter connection tracking on all pod traffic.
	InstallNoConntrackIptRules = false

	// WireguardSubnetV4 is a default wireguard tunnel subnet
	WireguardSubnetV4 = "172.16.43.0/24"

	// WireguardSubnetV6 is a default wireguard tunnel subnet
	WireguardSubnetV6 = "fdc9:281f:04d7:9ee9::1/64"

	// ExternalClusterIP enables cluster external access to ClusterIP services.
	// Defaults to false to retain prior behaviour of not routing external packets to ClusterIPs.
	ExternalClusterIP = false

	// EnableICMPRules enables ICMP-based rule support for Cilium Network Policies.
	EnableICMPRules = true

	// RoutingMode enables choosing between native routing mode or tunneling mode.
	RoutingMode = "tunnel"

	// TunnelProtocol is the default tunneling protocol
	TunnelProtocol = "vxlan"

	// Use the CiliumInternalIPs (vs. NodeInternalIPs) for IPsec encapsulation.
	UseCiliumInternalIPForIPsec = false

	// TunnelPortVXLAN is the default VXLAN port
	TunnelPortVXLAN = 8472
	// TunnelPortGeneve is the default Geneve port
	TunnelPortGeneve = 6081

	// ARPBaseReachableTime resembles the kernel's NEIGH_VAR_BASE_REACHABLE_TIME which defaults to 30 seconds.
	ARPBaseReachableTime = 30 * time.Second

	// EnableVTEP enables VXLAN Tunnel Endpoint (VTEP) Integration
	EnableVTEP     = false
	MaxVTEPDevices = 8

	// Enable BGP control plane features.
	EnableBGPControlPlane = false

	// EnableK8sNetworkPolicy enables support for K8s NetworkPolicy.
	EnableK8sNetworkPolicy = true
)

var (
	// BPFEventBufferConfigs contains default configuration entries for bpf map event buffers.
	// These are to be merged with the client configuration to create the final config.
	// Note: The TTL corresponds to GC interval times, which is a somewhat expensive operation.
	// Under the worst case GC may need to memcopy almost the entire buffer, which will
	// cause memory spikes. Be mindful of this when increasing the default buffer configurations.
	BPFEventBufferConfigs = map[string]string{
		"cilium_lxc": "enabled,128,0",
		// cilium_ipcache is the likely the most useful use of this feature, but also has
		// the highest churn.
		"cilium_ipcache":           "enabled,1024,0",
		"cilium_tunnel_map":        "enabled,128,0",
		"cilium_lb_affinity_match": "enabled,128,0",

		// ip4
		"cilium_lb4_services_v2":    "enabled,128,0",
		"cilium_lb4_backends_v2":    "enabled,128,0",
		"cilium_lb4_reverse_nat":    "enabled,128,0",
		"cilium_lb4_backends_v3":    "enabled,128,0",
		"cilium_lb4_source_range":   "enabled,128,0",
		"cilium_lb4_affinity_match": "enabled,128,0",

		// ip6
		"cilium_lb6_services_v2":    "enabled,128,0",
		"cilium_lb6_backends_v2":    "enabled,128,0",
		"cilium_lb6_reverse_nat":    "enabled,128,0",
		"cilium_lb6_backends_v3":    "enabled,128,0",
		"cilium_lb6_source_range":   "enabled,128,0",
		"cilium_lb6_affinity_match": "enabled,128,0",
	}
)

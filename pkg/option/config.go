// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	clustermeshTypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/version"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "config")
)

const (
	// AgentHealthPort is the TCP port for agent health status API
	AgentHealthPort = "agent-health-port"

	// ClusterHealthPort is the TCP port for cluster-wide network connectivity health API
	ClusterHealthPort = "cluster-health-port"

	// ClusterMeshHealthPort is the TCP port for ClusterMesh apiserver health API
	ClusterMeshHealthPort = "clustermesh-health-port"

	// AgentLabels are additional labels to identify this agent
	AgentLabels = "agent-labels"

	// AllowICMPFragNeeded allows ICMP Fragmentation Needed type packets in policy.
	AllowICMPFragNeeded = "allow-icmp-frag-needed"

	// AllowLocalhost is the policy when to allow local stack to reach local endpoints { auto | always | policy }
	AllowLocalhost = "allow-localhost"

	// AllowLocalhostAuto defaults to policy except when running in
	// Kubernetes where it then defaults to "always"
	AllowLocalhostAuto = "auto"

	// AllowLocalhostAlways always allows the local stack to reach local
	// endpoints
	AllowLocalhostAlways = "always"

	// AllowLocalhostPolicy requires a policy rule to allow the local stack
	// to reach particular endpoints or policy enforcement must be
	// disabled.
	AllowLocalhostPolicy = "policy"

	// AnnotateK8sNode enables annotating a kubernetes node while bootstrapping
	// the daemon, which can also be disbled using this option.
	AnnotateK8sNode = "annotate-k8s-node"

	// ARPPingRefreshPeriod is the ARP entries refresher period
	ARPPingRefreshPeriod = "arping-refresh-period"

	// EnableL2NeighDiscovery determines if cilium should perform L2 neighbor
	// discovery.
	EnableL2NeighDiscovery = "enable-l2-neigh-discovery"

	// BPFRoot is the Path to BPF filesystem
	BPFRoot = "bpf-root"

	// CertsDirectory is the root directory used to find out certificates used
	// in L7 HTTPs policy enforcement.
	CertsDirectory = "certificates-directory"

	// CGroupRoot is the path to Cgroup2 filesystem
	CGroupRoot = "cgroup-root"

	// CompilerFlags allow to specify extra compiler commands for advanced debugging
	CompilerFlags = "cflags"

	// ConfigFile is the Configuration file (default "$HOME/ciliumd.yaml")
	ConfigFile = "config"

	// ConfigDir is the directory that contains a file for each option where
	// the filename represents the option name and the content of that file
	// represents the value of that option.
	ConfigDir = "config-dir"

	// ConntrackGCInterval is the name of the ConntrackGCInterval option
	ConntrackGCInterval = "conntrack-gc-interval"

	// DebugArg is the argument enables debugging mode
	DebugArg = "debug"

	// DebugVerbose is the argument enables verbose log message for particular subsystems
	DebugVerbose = "debug-verbose"

	// Devices facing cluster/external network for attaching bpf_host
	Devices = "devices"

	// DirectRoutingDevice is the name of a device used to connect nodes in
	// direct routing mode (only required by BPF NodePort)
	DirectRoutingDevice = "direct-routing-device"

	// LBDevInheritIPAddr is device name which IP addr is inherited by devices
	// running BPF loadbalancer program
	LBDevInheritIPAddr = "bpf-lb-dev-ip-addr-inherit"

	// DisableConntrack disables connection tracking
	DisableConntrack = "disable-conntrack"

	// DisableEnvoyVersionCheck do not perform Envoy binary version check on startup
	DisableEnvoyVersionCheck = "disable-envoy-version-check"

	// EnablePolicy enables policy enforcement in the agent.
	EnablePolicy = "enable-policy"

	// EnableExternalIPs enables implementation of k8s services with externalIPs in datapath
	EnableExternalIPs = "enable-external-ips"

	// K8sEnableEndpointSlice enables the k8s EndpointSlice feature into Cilium
	K8sEnableEndpointSlice = "enable-k8s-endpoint-slice"

	// EnableL7Proxy is the name of the option to enable L7 proxy
	EnableL7Proxy = "enable-l7-proxy"

	// EnableTracing enables tracing mode in the agent.
	EnableTracing = "enable-tracing"

	// Add unreachable routes on pod deletion
	EnableUnreachableRoutes = "enable-unreachable-routes"

	// EncryptInterface enables encryption on specified interface
	EncryptInterface = "encrypt-interface"

	// EncryptNode enables node IP encryption
	EncryptNode = "encrypt-node"

	// EnvoyLog sets the path to a separate Envoy log file, if any
	EnvoyLog = "envoy-log"

	// GopsPort is the TCP port for the gops server.
	GopsPort = "gops-port"

	// ProxyPrometheusPort specifies the port to serve Cilium host proxy metrics on.
	ProxyPrometheusPort = "proxy-prometheus-port"

	// ProxyMaxRequestsPerConnection specifies the max_requests_per_connection setting for the proxy
	ProxyMaxRequestsPerConnection = "proxy-max-requests-per-connection"

	// ProxyMaxConnectionDuration specifies the max_connection_duration setting for the proxy in seconds
	ProxyMaxConnectionDuration = "proxy-max-connection-duration-seconds"

	// FixedIdentityMapping is the key-value for the fixed identity mapping
	// which allows to use reserved label for fixed identities
	FixedIdentityMapping = "fixed-identity-mapping"

	// IPv4Range is the per-node IPv4 endpoint prefix, e.g. 10.16.0.0/16
	IPv4Range = "ipv4-range"

	// IPv6Range is the per-node IPv6 endpoint prefix, must be /96, e.g. fd02:1:1::/96
	IPv6Range = "ipv6-range"

	// IPv4ServiceRange is the Kubernetes IPv4 services CIDR if not inside cluster prefix
	IPv4ServiceRange = "ipv4-service-range"

	// IPv6ServiceRange is the Kubernetes IPv6 services CIDR if not inside cluster prefix
	IPv6ServiceRange = "ipv6-service-range"

	// ModePreFilterNative for loading progs with xdpdrv
	ModePreFilterNative = XDPModeNative

	// ModePreFilterGeneric for loading progs with xdpgeneric
	ModePreFilterGeneric = XDPModeGeneric

	// IPv6ClusterAllocCIDRName is the name of the IPv6ClusterAllocCIDR option
	IPv6ClusterAllocCIDRName = "ipv6-cluster-alloc-cidr"

	// K8sRequireIPv4PodCIDRName is the name of the K8sRequireIPv4PodCIDR option
	K8sRequireIPv4PodCIDRName = "k8s-require-ipv4-pod-cidr"

	// K8sRequireIPv6PodCIDRName is the name of the K8sRequireIPv6PodCIDR option
	K8sRequireIPv6PodCIDRName = "k8s-require-ipv6-pod-cidr"

	// K8sWatcherEndpointSelector specifies the k8s endpoints that Cilium
	// should watch for.
	K8sWatcherEndpointSelector = "k8s-watcher-endpoint-selector"

	// K8sAPIServer is the kubernetes api address server (for https use --k8s-kubeconfig-path instead)
	K8sAPIServer = "k8s-api-server"

	// K8sKubeConfigPath is the absolute path of the kubernetes kubeconfig file
	K8sKubeConfigPath = "k8s-kubeconfig-path"

	// K8sServiceCacheSize is service cache size for cilium k8s package.
	K8sServiceCacheSize = "k8s-service-cache-size"

	// K8sSyncTimeout is the timeout to synchronize all resources with k8s.
	K8sSyncTimeoutName = "k8s-sync-timeout"

	// AllocatorListTimeout is the timeout to list initial allocator state.
	AllocatorListTimeoutName = "allocator-list-timeout"

	// KeepConfig when restoring state, keeps containers' configuration in place
	KeepConfig = "keep-config"

	// KVStore key-value store type
	KVStore = "kvstore"

	// KVStoreOpt key-value store options
	KVStoreOpt = "kvstore-opt"

	// Labels is the list of label prefixes used to determine identity of an endpoint
	Labels = "labels"

	// LabelPrefixFile is the valid label prefixes file path
	LabelPrefixFile = "label-prefix-file"

	// EnableHostFirewall enables network policies for the host
	EnableHostFirewall = "enable-host-firewall"

	// EnableHostPort enables HostPort forwarding implemented by Cilium in BPF
	EnableHostPort = "enable-host-port"

	// EnableHostLegacyRouting enables the old routing path via stack.
	EnableHostLegacyRouting = "enable-host-legacy-routing"

	// EnableNodePort enables NodePort services implemented by Cilium in BPF
	EnableNodePort = "enable-node-port"

	// EnableSVCSourceRangeCheck enables check of service source range checks
	EnableSVCSourceRangeCheck = "enable-svc-source-range-check"

	// NodePortMode indicates in which mode NodePort implementation should run
	// ("snat", "dsr" or "hybrid")
	NodePortMode = "node-port-mode"

	// NodePortAlg indicates which algorithm is used for backend selection
	// ("random" or "maglev")
	NodePortAlg = "node-port-algorithm"

	// NodePortAcceleration indicates whether NodePort should be accelerated
	// via XDP ("none", "generic" or "native")
	NodePortAcceleration = "node-port-acceleration"

	// Alias to NodePortMode
	LoadBalancerMode = "bpf-lb-mode"

	// Alias to DSR dispatch method
	LoadBalancerDSRDispatch = "bpf-lb-dsr-dispatch"

	// Alias to DSR L4 translation method
	LoadBalancerDSRL4Xlate = "bpf-lb-dsr-l4-xlate"

	// Alias to DSR/IPIP IPv4 source CIDR
	LoadBalancerRSSv4CIDR = "bpf-lb-rss-ipv4-src-cidr"

	// Alias to DSR/IPIP IPv6 source CIDR
	LoadBalancerRSSv6CIDR = "bpf-lb-rss-ipv6-src-cidr"

	// Alias to NodePortAlg
	LoadBalancerAlg = "bpf-lb-algorithm"

	// Alias to NodePortAcceleration
	LoadBalancerAcceleration = "bpf-lb-acceleration"

	// MaglevTableSize determines the size of the backend table per service
	MaglevTableSize = "bpf-lb-maglev-table-size"

	// MaglevHashSeed contains the cluster-wide seed for the hash
	MaglevHashSeed = "bpf-lb-maglev-hash-seed"

	// NodePortBindProtection rejects bind requests to NodePort service ports
	NodePortBindProtection = "node-port-bind-protection"

	// NodePortRange defines a custom range where to look up NodePort services
	NodePortRange = "node-port-range"

	// EnableAutoProtectNodePortRange enables appending NodePort range to
	// net.ipv4.ip_local_reserved_ports if it overlaps with ephemeral port
	// range (net.ipv4.ip_local_port_range)
	EnableAutoProtectNodePortRange = "enable-auto-protect-node-port-range"

	// KubeProxyReplacement controls how to enable kube-proxy replacement
	// features in BPF datapath
	KubeProxyReplacement = "kube-proxy-replacement"

	// EnableSessionAffinity enables a support for service sessionAffinity
	EnableSessionAffinity = "enable-session-affinity"

	EnableServiceTopology = "enable-service-topology"

	// EnableIdentityMark enables setting the mark field with the identity for
	// local traffic. This may be disabled if chaining modes and Cilium use
	// conflicting marks.
	EnableIdentityMark = "enable-identity-mark"

	// EnableBandwidthManager enables EDT-based pacing
	EnableBandwidthManager = "enable-bandwidth-manager"

	// EnableBBR enables BBR TCP congestion control for the node including Pods
	EnableBBR = "enable-bbr"

	// EnableRecorder enables the datapath pcap recorder
	EnableRecorder = "enable-recorder"

	// EnableLocalRedirectPolicy enables support for local redirect policy
	EnableLocalRedirectPolicy = "enable-local-redirect-policy"

	// EnableMKE enables MKE specific 'chaining' for kube-proxy replacement
	EnableMKE = "enable-mke"

	// CgroupPathMKE points to the cgroupv1 net_cls mount instance
	CgroupPathMKE = "mke-cgroup-mount"

	// LibDir enables the directory path to store runtime build environment
	LibDir = "lib-dir"

	// LogDriver sets logging endpoints to use for example syslog, fluentd
	LogDriver = "log-driver"

	// LogOpt sets log driver options for cilium
	LogOpt = "log-opt"

	// Logstash enables logstash integration
	Logstash = "logstash"

	// EnableIPv4Masquerade masquerades IPv4 packets from endpoints leaving the host.
	EnableIPv4Masquerade = "enable-ipv4-masquerade"

	// EnableIPv6Masquerade masquerades IPv6 packets from endpoints leaving the host.
	EnableIPv6Masquerade = "enable-ipv6-masquerade"

	// EnableBPFClockProbe selects a more efficient source clock (jiffies vs ktime)
	EnableBPFClockProbe = "enable-bpf-clock-probe"

	// EnableBPFMasquerade masquerades packets from endpoints leaving the host with BPF instead of iptables
	EnableBPFMasquerade = "enable-bpf-masquerade"

	// DeriveMasqIPAddrFromDevice is device name which IP addr is used for BPF masquerades
	DeriveMasqIPAddrFromDevice = "derive-masquerade-ip-addr-from-device"

	// EnableIPMasqAgent enables BPF ip-masq-agent
	EnableIPMasqAgent = "enable-ip-masq-agent"

	// EnableIPv4EgressGateway enables the IPv4 egress gateway
	EnableIPv4EgressGateway = "enable-ipv4-egress-gateway"

	// EnableEnvoyConfig enables processing of CiliumClusterwideEnvoyConfig and CiliumEnvoyConfig CRDs
	EnableEnvoyConfig = "enable-envoy-config"

	// EnvoyConfigTimeout determines how long to wait Envoy to N/ACK resources
	EnvoyConfigTimeout = "envoy-config-timeout"

	// IPMasqAgentConfigPath is the configuration file path
	IPMasqAgentConfigPath = "ip-masq-agent-config-path"

	// InstallIptRules sets whether Cilium should install any iptables in general
	InstallIptRules = "install-iptables-rules"

	// InstallNoConntrackIptRules instructs Cilium to install Iptables rules
	// to skip netfilter connection tracking on all pod traffic.
	InstallNoConntrackIptRules = "install-no-conntrack-iptables-rules"

	IPTablesLockTimeout = "iptables-lock-timeout"

	// IPTablesRandomFully sets iptables flag random-fully on masquerading rules
	IPTablesRandomFully = "iptables-random-fully"

	// IPv6NodeAddr is the IPv6 address of node
	IPv6NodeAddr = "ipv6-node"

	// IPv4NodeAddr is the IPv4 address of node
	IPv4NodeAddr = "ipv4-node"

	// Restore restores state, if possible, from previous daemon
	Restore = "restore"

	// SidecarIstioProxyImage regular expression matching compatible Istio sidecar istio-proxy container image names
	SidecarIstioProxyImage = "sidecar-istio-proxy-image"

	// SocketPath sets daemon's socket path to listen for connections
	SocketPath = "socket-path"

	// StateDir is the directory path to store runtime state
	StateDir = "state-dir"

	// TracePayloadlen length of payload to capture when tracing
	TracePayloadlen = "trace-payloadlen"

	// Version prints the version information
	Version = "version"

	// PProf enables serving the pprof debugging API
	PProf = "pprof"

	// PProfPort is the port that the pprof listens on
	PProfPort = "pprof-port"

	// EnableXDPPrefilter enables XDP-based prefiltering
	EnableXDPPrefilter = "enable-xdp-prefilter"

	// PrefilterDevice is the device facing external network for XDP prefiltering
	PrefilterDevice = "prefilter-device"

	// PrefilterMode { "+ModePreFilterNative+" | "+ModePreFilterGeneric+" } (default: "+option.ModePreFilterNative+")
	PrefilterMode = "prefilter-mode"

	ProcFs = "procfs"

	// PrometheusServeAddr IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	PrometheusServeAddr = "prometheus-serve-addr"

	// CMDRef is the path to cmdref output directory
	CMDRef = "cmdref"

	// DNSMaxIPsPerRestoredRule defines the maximum number of IPs to maintain
	// for each FQDN selector in endpoint's restored DNS rules
	DNSMaxIPsPerRestoredRule = "dns-max-ips-per-restored-rule"

	// DNSPolicyUnloadOnShutdown is the name of the dns-policy-unload-on-shutdown option.
	DNSPolicyUnloadOnShutdown = "dns-policy-unload-on-shutdown"

	// ToFQDNsMinTTL is the minimum time, in seconds, to use DNS data for toFQDNs policies.
	ToFQDNsMinTTL = "tofqdns-min-ttl"

	// ToFQDNsProxyPort is the global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port.
	ToFQDNsProxyPort = "tofqdns-proxy-port"

	// ToFQDNsMaxIPsPerHost defines the maximum number of IPs to maintain
	// for each FQDN name in an endpoint's FQDN cache
	ToFQDNsMaxIPsPerHost = "tofqdns-endpoint-max-ip-per-hostname"

	// ToFQDNsMaxDeferredConnectionDeletes defines the maximum number of IPs to
	// retain for expired DNS lookups with still-active connections"
	ToFQDNsMaxDeferredConnectionDeletes = "tofqdns-max-deferred-connection-deletes"

	// ToFQDNsIdleConnectionGracePeriod defines the connection idle time during which
	// previously active connections with expired DNS lookups are still considered alive
	ToFQDNsIdleConnectionGracePeriod = "tofqdns-idle-connection-grace-period"

	// ToFQDNsPreCache is a path to a file with DNS cache data to insert into the
	// global cache on startup.
	// The file is not re-read after agent start.
	ToFQDNsPreCache = "tofqdns-pre-cache"

	// ToFQDNsEnableDNSCompression allows the DNS proxy to compress responses to
	// endpoints that are larger than 512 Bytes or the EDNS0 option, if present.
	ToFQDNsEnableDNSCompression = "tofqdns-enable-dns-compression"

	// MTUName is the name of the MTU option
	MTUName = "mtu"

	// RouteMetric is the name of the route-metric option
	RouteMetric = "route-metric"

	// DatapathMode is the name of the DatapathMode option
	DatapathMode = "datapath-mode"

	// IpvlanMasterDevice is the name of the IpvlanMasterDevice option
	IpvlanMasterDevice = "ipvlan-master-device"

	// EnableHostReachableServices is the name of the EnableHostReachableServices option
	EnableHostReachableServices = "enable-host-reachable-services"

	// BPFSocketLBHostnsOnly is the name of the BPFSocketLBHostnsOnly option
	BPFSocketLBHostnsOnly = "bpf-lb-sock-hostns-only"

	// HostReachableServicesProtos is the name of the HostReachableServicesProtos option
	HostReachableServicesProtos = "host-reachable-services-protos"

	// HostServicesTCP is the name of EnableHostServicesTCP config
	HostServicesTCP = "tcp"

	// HostServicesUDP is the name of EnableHostServicesUDP config
	HostServicesUDP = "udp"

	// TunnelName is the name of the Tunnel option
	TunnelName = "tunnel"
	// TunnelPortName is the name of the TunnelPort option
	TunnelPortName = "tunnel-port"

	// SingleClusterRouteName is the name of the SingleClusterRoute option
	//
	// SingleClusterRoute enables use of a single route covering the entire
	// cluster CIDR to point to the cilium_host interface instead of using
	// a separate route for each cluster node CIDR. This option is not
	// compatible with Tunnel=TunnelDisabled
	SingleClusterRouteName = "single-cluster-route"

	// MonitorAggregationName specifies the MonitorAggregationLevel on the
	// comandline.
	MonitorAggregationName = "monitor-aggregation"

	// MonitorAggregationInterval configures interval for monitor-aggregation
	MonitorAggregationInterval = "monitor-aggregation-interval"

	// MonitorAggregationFlags configures TCP flags used by monitor aggregation.
	MonitorAggregationFlags = "monitor-aggregation-flags"

	// ciliumEnvPrefix is the prefix used for environment variables
	ciliumEnvPrefix = "CILIUM_"

	// ClusterName is the name of the ClusterName option
	ClusterName = "cluster-name"

	// ClusterIDName is the name of the ClusterID option
	ClusterIDName = "cluster-id"

	// ClusterMeshConfigName is the name of the ClusterMeshConfig option
	ClusterMeshConfigName = "clustermesh-config"

	// CTMapEntriesGlobalTCPDefault is the default maximum number of entries
	// in the TCP CT table.
	CTMapEntriesGlobalTCPDefault = 2 << 18 // 512Ki

	// CTMapEntriesGlobalAnyDefault is the default maximum number of entries
	// in the non-TCP CT table.
	CTMapEntriesGlobalAnyDefault = 2 << 17 // 256Ki

	// CTMapEntriesGlobalTCPName configures max entries for the TCP CT
	// table.
	CTMapEntriesGlobalTCPName = "bpf-ct-global-tcp-max"

	// CTMapEntriesGlobalAnyName configures max entries for the non-TCP CT
	// table.
	CTMapEntriesGlobalAnyName = "bpf-ct-global-any-max"

	// CTMapEntriesTimeout* name option and default value mappings
	CTMapEntriesTimeoutSYNName    = "bpf-ct-timeout-regular-tcp-syn"
	CTMapEntriesTimeoutFINName    = "bpf-ct-timeout-regular-tcp-fin"
	CTMapEntriesTimeoutTCPName    = "bpf-ct-timeout-regular-tcp"
	CTMapEntriesTimeoutAnyName    = "bpf-ct-timeout-regular-any"
	CTMapEntriesTimeoutSVCTCPName = "bpf-ct-timeout-service-tcp"
	CTMapEntriesTimeoutSVCAnyName = "bpf-ct-timeout-service-any"

	// NATMapEntriesGlobalDefault holds the default size of the NAT map
	// and is 2/3 of the full CT size as a heuristic
	NATMapEntriesGlobalDefault = int((CTMapEntriesGlobalTCPDefault + CTMapEntriesGlobalAnyDefault) * 2 / 3)

	// SockRevNATMapEntriesDefault holds the default size of the SockRev NAT map
	// and is the same size of CTMapEntriesGlobalAnyDefault as a heuristic given
	// that sock rev NAT is mostly used for UDP and getpeername only.
	SockRevNATMapEntriesDefault = CTMapEntriesGlobalAnyDefault

	// MapEntriesGlobalDynamicSizeRatioName is the name of the option to
	// set the ratio of total system memory to use for dynamic sizing of the
	// CT, NAT, Neighbor and SockRevNAT BPF maps.
	MapEntriesGlobalDynamicSizeRatioName = "bpf-map-dynamic-size-ratio"

	// LimitTableAutoGlobalTCPMin defines the minimum TCP CT table limit for
	// dynamic size ration calculation.
	LimitTableAutoGlobalTCPMin = 1 << 17 // 128Ki entries

	// LimitTableAutoGlobalAnyMin defines the minimum UDP CT table limit for
	// dynamic size ration calculation.
	LimitTableAutoGlobalAnyMin = 1 << 16 // 64Ki entries

	// LimitTableAutoNatGlobalMin defines the minimum NAT limit for dynamic size
	// ration calculation.
	LimitTableAutoNatGlobalMin = 1 << 17 // 128Ki entries

	// LimitTableAutoSockRevNatMin defines the minimum SockRevNAT limit for
	// dynamic size ration calculation.
	LimitTableAutoSockRevNatMin = 1 << 16 // 64Ki entries

	// LimitTableMin defines the minimum CT or NAT table limit
	LimitTableMin = 1 << 10 // 1Ki entries

	// LimitTableMax defines the maximum CT or NAT table limit
	LimitTableMax = 1 << 24 // 16Mi entries (~1GiB of entries per map)

	// PolicyMapMin defines the minimum policy map limit.
	PolicyMapMin = 1 << 8

	// PolicyMapMax defines the maximum policy map limit.
	PolicyMapMax = 1 << 16

	// FragmentsMapMin defines the minimum fragments map limit.
	FragmentsMapMin = 1 << 8

	// FragmentsMapMax defines the maximum fragments map limit.
	FragmentsMapMax = 1 << 16

	// NATMapEntriesGlobalName configures max entries for BPF NAT table
	NATMapEntriesGlobalName = "bpf-nat-global-max"

	// NeighMapEntriesGlobalName configures max entries for BPF neighbor table
	NeighMapEntriesGlobalName = "bpf-neigh-global-max"

	// PolicyMapEntriesName configures max entries for BPF policymap.
	PolicyMapEntriesName = "bpf-policy-map-max"

	// SockRevNatEntriesName configures max entries for BPF sock reverse nat
	// entries.
	SockRevNatEntriesName = "bpf-sock-rev-map-max"

	// LogSystemLoadConfigName is the name of the option to enable system
	// load loggging
	LogSystemLoadConfigName = "log-system-load"

	// PrependIptablesChainsName is the name of the option to enable
	// prepending iptables chains instead of appending
	PrependIptablesChainsName = "prepend-iptables-chains"

	// DisableCiliumEndpointCRDName is the name of the option to disable
	// use of the CEP CRD
	DisableCiliumEndpointCRDName = "disable-endpoint-crd"

	// MaxCtrlIntervalName and MaxCtrlIntervalNameEnv allow configuration
	// of MaxControllerInterval.
	MaxCtrlIntervalName = "max-controller-interval"

	// SockopsEnableName is the name of the option to enable sockops
	SockopsEnableName = "sockops-enable"

	// K8sNamespaceName is the name of the K8sNamespace option
	K8sNamespaceName = "k8s-namespace"

	// JoinClusterName is the name of the JoinCluster Option
	JoinClusterName = "join-cluster"

	// EnableIPv4Name is the name of the option to enable IPv4 support
	EnableIPv4Name = "enable-ipv4"

	// EnableIPv6Name is the name of the option to enable IPv6 support
	EnableIPv6Name = "enable-ipv6"

	// EnableIPv6NDPName is the name of the option to enable IPv6 NDP support
	EnableIPv6NDPName = "enable-ipv6-ndp"

	// IPv6MCastDevice is the name of the option to select IPv6 multicast device
	IPv6MCastDevice = "ipv6-mcast-device"

	// EnableMonitor is the name of the option to enable the monitor socket
	EnableMonitorName = "enable-monitor"

	// MonitorQueueSizeName is the name of the option MonitorQueueSize
	MonitorQueueSizeName = "monitor-queue-size"

	//FQDNRejectResponseCode is the name for the option for dns-proxy reject response code
	FQDNRejectResponseCode = "tofqdns-dns-reject-response-code"

	// FQDNProxyDenyWithNameError is useful when stub resolvers, like the one
	// in Alpine Linux's libc (musl), treat a REFUSED as a resolution error.
	// This happens when trying a DNS search list, as in kubernetes, and breaks
	// even whitelisted DNS names.
	FQDNProxyDenyWithNameError = "nameError"

	// FQDNProxyDenyWithRefused is the response code for Domain refused. It is
	// the default for denied DNS requests.
	FQDNProxyDenyWithRefused = "refused"

	// FQDNProxyResponseMaxDelay is the maximum time the proxy holds back a response
	FQDNProxyResponseMaxDelay = "tofqdns-proxy-response-max-delay"

	// PreAllocateMapsName is the name of the option PreAllocateMaps
	PreAllocateMapsName = "preallocate-bpf-maps"

	// EnableBPFTProxy option supports enabling or disabling BPF TProxy.
	EnableBPFTProxy = "enable-bpf-tproxy"

	// EnableXTSocketFallbackName is the name of the EnableXTSocketFallback option
	EnableXTSocketFallbackName = "enable-xt-socket-fallback"

	// EnableAutoDirectRoutingName is the name for the EnableAutoDirectRouting option
	EnableAutoDirectRoutingName = "auto-direct-node-routes"

	// EnableIPSecName is the name of the option to enable IPSec
	EnableIPSecName = "enable-ipsec"

	// IPSecKeyFileName is the name of the option for ipsec key file
	IPSecKeyFileName = "ipsec-key-file"

	// EnableWireguard is the name of the option to enable wireguard
	EnableWireguard = "enable-wireguard"

	// EnableWireguardUserspaceFallback is the name of the option that enables the fallback to wireguard userspace mode
	EnableWireguardUserspaceFallback = "enable-wireguard-userspace-fallback"

	// KVstoreLeaseTTL is the time-to-live for lease in kvstore.
	KVstoreLeaseTTL = "kvstore-lease-ttl"

	// KVstoreMaxConsecutiveQuorumErrorsName is the maximum number of acceptable
	// kvstore consecutive quorum errors before the agent assumes permanent failure
	KVstoreMaxConsecutiveQuorumErrorsName = "kvstore-max-consecutive-quorum-errors"

	// KVstorePeriodicSync is the time interval in which periodic
	// synchronization with the kvstore occurs
	KVstorePeriodicSync = "kvstore-periodic-sync"

	// KVstoreConnectivityTimeout is the timeout when performing kvstore operations
	KVstoreConnectivityTimeout = "kvstore-connectivity-timeout"

	// IPAllocationTimeout is the timeout when allocating CIDRs
	IPAllocationTimeout = "ip-allocation-timeout"

	// IdentityChangeGracePeriod is the name of the
	// IdentityChangeGracePeriod option
	IdentityChangeGracePeriod = "identity-change-grace-period"

	// IdentityRestoreGracePeriod is the name of the
	// IdentityRestoreGracePeriod option
	IdentityRestoreGracePeriod = "identity-restore-grace-period"

	// EnableHealthChecking is the name of the EnableHealthChecking option
	EnableHealthChecking = "enable-health-checking"

	// EnableEndpointHealthChecking is the name of the EnableEndpointHealthChecking option
	EnableEndpointHealthChecking = "enable-endpoint-health-checking"

	// EnableHealthCheckNodePort is the name of the EnableHealthCheckNodePort option
	EnableHealthCheckNodePort = "enable-health-check-nodeport"

	// PolicyQueueSize is the size of the queues utilized by the policy
	// repository.
	PolicyQueueSize = "policy-queue-size"

	// EndpointQueueSize is the size of the EventQueue per-endpoint.
	EndpointQueueSize = "endpoint-queue-size"

	// EndpointGCInterval interval to attempt garbage collection of
	// endpoints that are no longer alive and healthy.
	EndpointGCInterval = "endpoint-gc-interval"

	// SelectiveRegeneration specifies whether only the endpoints which policy
	// changes select should be regenerated upon policy changes.
	SelectiveRegeneration = "enable-selective-regeneration"

	// K8sEventHandover is the name of the K8sEventHandover option
	K8sEventHandover = "enable-k8s-event-handover"

	// Metrics represents the metrics subsystem that Cilium should expose
	// to prometheus.
	Metrics = "metrics"

	// LoopbackIPv4 is the address to use for service loopback SNAT
	LoopbackIPv4 = "ipv4-service-loopback-address"

	// LocalRouterIPv4 is the link-local IPv4 address to use for Cilium router device
	LocalRouterIPv4 = "local-router-ipv4"

	// LocalRouterIPv6 is the link-local IPv6 address to use for Cilium router device
	LocalRouterIPv6 = "local-router-ipv6"

	// EndpointInterfaceNamePrefix is the prefix name of the interface
	// names shared by all endpoints
	EndpointInterfaceNamePrefix = "endpoint-interface-name-prefix"

	// ForceLocalPolicyEvalAtSource forces a policy decision at the source
	// endpoint for all local communication
	ForceLocalPolicyEvalAtSource = "force-local-policy-eval-at-source"

	// SkipCRDCreation specifies whether the CustomResourceDefinition will be
	// created by the daemon
	SkipCRDCreation = "skip-crd-creation"

	// EnableEndpointRoutes enables use of per endpoint routes
	EnableEndpointRoutes = "enable-endpoint-routes"

	// ExcludeLocalAddress excludes certain addresses to be recognized as a
	// local address
	ExcludeLocalAddress = "exclude-local-address"

	// IPv4PodSubnets A list of IPv4 subnets that pods may be
	// assigned from. Used with CNI chaining where IPs are not directly managed
	// by Cilium.
	IPv4PodSubnets = "ipv4-pod-subnets"

	// IPv6PodSubnets A list of IPv6 subnets that pods may be
	// assigned from. Used with CNI chaining where IPs are not directly managed
	// by Cilium.
	IPv6PodSubnets = "ipv6-pod-subnets"

	// IPAM is the IPAM method to use
	IPAM = "ipam"

	// XDPModeNative for loading progs with XDPModeLinkDriver
	XDPModeNative = "native"

	// XDPModeGeneric for loading progs with XDPModeLinkGeneric
	XDPModeGeneric = "testing-only"

	// XDPModeDisabled for not having XDP enabled
	XDPModeDisabled = "disabled"

	// XDPModeLinkDriver is the tc selector for native XDP
	XDPModeLinkDriver = "xdpdrv"

	// XDPModeLinkGeneric is the tc selector for generic XDP
	XDPModeLinkGeneric = "xdpgeneric"

	// XDPModeLinkNone for not having XDP enabled
	XDPModeLinkNone = XDPModeDisabled

	// K8sClientQPSLimit is the queries per second limit for the K8s client. Defaults to k8s client defaults.
	K8sClientQPSLimit = "k8s-client-qps"

	// K8sClientBurst is the burst value allowed for the K8s client. Defaults to k8s client defaults.
	K8sClientBurst = "k8s-client-burst"

	// AutoCreateCiliumNodeResource enables automatic creation of a
	// CiliumNode resource for the local node
	AutoCreateCiliumNodeResource = "auto-create-cilium-node-resource"

	// NativeRoutingCIDR describes a v4 CIDR in which pod IPs are routable
	NativeRoutingCIDR = "native-routing-cidr"

	// IPv4NativeRoutingCIDR describes a v4 CIDR in which pod IPs are routable
	IPv4NativeRoutingCIDR = "ipv4-native-routing-cidr"

	// IPv6NativeRoutingCIDR describes a v6 CIDR in which pod IPs are routable
	IPv6NativeRoutingCIDR = "ipv6-native-routing-cidr"

	// EgressMasqueradeInterfaces is the selector used to select interfaces
	// subject to egress masquerading
	EgressMasqueradeInterfaces = "egress-masquerade-interfaces"

	// PolicyTriggerInterval is the amount of time between triggers of policy
	// updates are invoked.
	PolicyTriggerInterval = "policy-trigger-interval"

	// IdentityAllocationMode specifies what mode to use for identity
	// allocation
	IdentityAllocationMode = "identity-allocation-mode"

	// IdentityAllocationModeKVstore enables use of a key-value store such
	// as etcd for identity allocation
	IdentityAllocationModeKVstore = "kvstore"

	// IdentityAllocationModeCRD enables use of Kubernetes CRDs for
	// identity allocation
	IdentityAllocationModeCRD = "crd"

	// DisableCNPStatusUpdates disables updating of CNP NodeStatus in the CNP
	// CRD.
	DisableCNPStatusUpdates = "disable-cnp-status-updates"

	// EnableLocalNodeRoute controls installation of the route which points
	// the allocation prefix of the local node.
	EnableLocalNodeRoute = "enable-local-node-route"

	// EnableWellKnownIdentities enables the use of well-known identities.
	// This is requires if identiy resolution is required to bring up the
	// control plane, e.g. when using the managed etcd feature
	EnableWellKnownIdentities = "enable-well-known-identities"

	// EnableRemoteNodeIdentity enables use of the remote-node identity
	EnableRemoteNodeIdentity = "enable-remote-node-identity"

	// PolicyAuditModeArg argument enables policy audit mode.
	PolicyAuditModeArg = "policy-audit-mode"

	// EnableHubble enables hubble in the agent.
	EnableHubble = "enable-hubble"

	// HubbleSocketPath specifies the UNIX domain socket for Hubble server to listen to.
	HubbleSocketPath = "hubble-socket-path"

	// HubbleListenAddress specifies address for Hubble server to listen to.
	HubbleListenAddress = "hubble-listen-address"

	// HubbleTLSDisabled allows the Hubble server to run on the given listen
	// address without TLS.
	HubbleTLSDisabled = "hubble-disable-tls"

	// HubbleTLSCertFile specifies the path to the public key file for the
	// Hubble server. The file must contain PEM encoded data.
	HubbleTLSCertFile = "hubble-tls-cert-file"

	// HubbleTLSKeyFile specifies the path to the private key file for the
	// Hubble server. The file must contain PEM encoded data.
	HubbleTLSKeyFile = "hubble-tls-key-file"

	// HubbleTLSClientCAFiles specifies the path to one or more client CA
	// certificates to use for TLS with mutual authentication (mTLS). The files
	// must contain PEM encoded data.
	HubbleTLSClientCAFiles = "hubble-tls-client-ca-files"

	// HubbleEventBufferCapacity specifies the capacity of Hubble events buffer.
	HubbleEventBufferCapacity = "hubble-event-buffer-capacity"

	// HubbleEventQueueSize specifies the buffer size of the channel to receive monitor events.
	HubbleEventQueueSize = "hubble-event-queue-size"

	// HubbleMetricsServer specifies the addresses to serve Hubble metrics on.
	HubbleMetricsServer = "hubble-metrics-server"

	// HubbleMetrics specifies enabled metrics and their configuration options.
	HubbleMetrics = "hubble-metrics"

	// HubbleExportFilePath specifies the filepath to write Hubble events to.
	// e.g. "/var/run/cilium/hubble/events.log"
	HubbleExportFilePath = "hubble-export-file-path"

	// HubbleExportFileMaxSizeMB specifies the file size in MB at which to rotate
	// the Hubble export file.
	HubbleExportFileMaxSizeMB = "hubble-export-file-max-size-mb"

	// HubbleExportFileMaxBacks specifies the number of rotated files to keep.
	HubbleExportFileMaxBackups = "hubble-export-file-max-backups"

	// HubbleExportFileCompress specifies whether rotated files are compressed.
	HubbleExportFileCompress = "hubble-export-file-compress"

	// EnableHubbleRecorderAPI specifies if the Hubble Recorder API should be served
	EnableHubbleRecorderAPI = "enable-hubble-recorder-api"

	// HubbleRecorderStoragePath specifies the directory in which pcap files
	// created via the Hubble Recorder API are stored
	HubbleRecorderStoragePath = "hubble-recorder-storage-path"

	// HubbleRecorderSinkQueueSize is the queue size for each recorder sink
	HubbleRecorderSinkQueueSize = "hubble-recorder-sink-queue-size"

	// DisableIptablesFeederRules specifies which chains will be excluded
	// when installing the feeder rules
	DisableIptablesFeederRules = "disable-iptables-feeder-rules"

	// K8sHeartbeatTimeout configures the timeout for apiserver heartbeat
	K8sHeartbeatTimeout = "k8s-heartbeat-timeout"

	// EndpointStatus enables population of information in the
	// CiliumEndpoint.Status resource
	EndpointStatus = "endpoint-status"

	// EndpointStatusPolicy enables CiliumEndpoint.Status.Policy
	EndpointStatusPolicy = "policy"

	// EndpointStatusHealth enables CilliumEndpoint.Status.Health
	EndpointStatusHealth = "health"

	// EndpointStatusControllers enables CiliumEndpoint.Status.Controllers
	EndpointStatusControllers = "controllers"

	// EndpointStatusLog enables CiliumEndpoint.Status.Log
	EndpointStatusLog = "log"

	// EndpointStatusState enables CiliumEndpoint.Status.State
	EndpointStatusState = "state"

	// EnableIPv4FragmentsTrackingName is the name of the option to enable
	// IPv4 fragments tracking for L4-based lookups. Needs LRU map support.
	EnableIPv4FragmentsTrackingName = "enable-ipv4-fragment-tracking"

	// FragmentsMapEntriesName configures max entries for BPF fragments
	// tracking map.
	FragmentsMapEntriesName = "bpf-fragments-map-max"

	// K8sEnableAPIDiscovery enables Kubernetes API discovery
	K8sEnableAPIDiscovery = "enable-k8s-api-discovery"

	// LBMapEntriesName configures max entries for BPF lbmap.
	LBMapEntriesName = "bpf-lb-map-max"

	// LBServiceMapMaxEntries configures max entries of bpf map for services.
	LBServiceMapMaxEntries = "bpf-lb-service-map-max"

	// LBBackendMapMaxEntries configures max entries of bpf map for service backends.
	LBBackendMapMaxEntries = "bpf-lb-service-backend-map-max"

	// LBRevNatMapMaxEntries configures max entries of bpf map for reverse NAT.
	LBRevNatMapMaxEntries = "bpf-lb-rev-nat-map-max"

	// LBAffinityMapMaxEntries configures max entries of bpf map for session affinity.
	LBAffinityMapMaxEntries = "bpf-lb-affinity-map-max"

	// LBSourceRangeMapMaxEntries configures max entries of bpf map for service source ranges.
	LBSourceRangeMapMaxEntries = "bpf-lb-source-range-map-max"

	// LBMaglevMapMaxEntries configures max entries of bpf map for Maglev.
	LBMaglevMapMaxEntries = "bpf-lb-maglev-map-max"

	// K8sServiceProxyName instructs Cilium to handle service objects only when
	// service.kubernetes.io/service-proxy-name label equals the provided value.
	K8sServiceProxyName = "k8s-service-proxy-name"

	// APIRateLimitName enables configuration of the API rate limits
	APIRateLimitName = "api-rate-limit"

	// CRDWaitTimeout is the timeout in which Cilium will exit if CRDs are not
	// available.
	CRDWaitTimeout = "crd-wait-timeout"

	// EgressMultiHomeIPRuleCompat instructs Cilium to use a new scheme to
	// store rules and routes under ENI and Azure IPAM modes, if false.
	// Otherwise, it will use the old scheme.
	EgressMultiHomeIPRuleCompat = "egress-multi-home-ip-rule-compat"

	// EnableBPFBypassFIBLookup instructs Cilium to enable the FIB lookup bypass
	// optimization for nodeport reverse NAT handling (DEPRECATED).
	EnableBPFBypassFIBLookup = "bpf-lb-bypass-fib-lookup"

	// EnableCustomCallsName is the name of the option to enable tail calls
	// for user-defined custom eBPF programs.
	EnableCustomCallsName = "enable-custom-calls"

	// BGPAnnounceLBIP announces service IPs of type LoadBalancer via BGP
	BGPAnnounceLBIP = "bgp-announce-lb-ip"

	// BGPAnnouncePodCIDR announces the node's pod CIDR via BGP
	BGPAnnouncePodCIDR = "bgp-announce-pod-cidr"

	// BGPConfigPath is the file path to the BGP configuration. It is
	// compatible with MetalLB's configuration.
	BGPConfigPath = "bgp-config-path"

	// ExternalClusterIPName is the name of the option to enable
	// cluster external access to ClusterIP services.
	ExternalClusterIPName = "bpf-lb-external-clusterip"

	// VLANBPFBypass instructs Cilium to bypass bpf logic for vlan tagged packets
	VLANBPFBypass = "vlan-bpf-bypass"

	// EnableICMPRules enables ICMP-based rule support for Cilium Network Policies.
	EnableICMPRules = "enable-icmp-rules"

	// BypassIPAvailabilityUponRestore bypasses the IP availability error
	// within IPAM upon endpoint restore and allows the use of the restored IP
	// regardless of whether it's available in the pool.
	BypassIPAvailabilityUponRestore = "bypass-ip-availability-upon-restore"

	// EnableK8sTerminatingEndpoint enables the option to auto detect terminating
	// state for endpoints in order to support graceful termination.
	EnableK8sTerminatingEndpoint = "enable-k8s-terminating-endpoint"

	// EnableVTEP enables cilium VXLAN VTEP integration
	EnableVTEP = "enable-vtep"

	// VTEP endpoint IPs
	VtepEndpoint = "vtep-endpoint"

	// VTEP CIDRs
	VtepCIDR = "vtep-cidr"

	// VTEP CIDR Mask applies to all VtepCIDR
	VtepMask = "vtep-mask"

	// VTEP MACs
	VtepMAC = "vtep-mac"

	// TCFilterPriority sets the priority of the cilium tc filter, enabling other
	// filters to be inserted prior to the cilium filter.
	TCFilterPriority = "bpf-filter-priority"

	// Flag to enable BGP control plane features
	EnableBGPControlPlane = "enable-bgp-control-plane"
)

// Default string arguments
var (
	FQDNRejectOptions = []string{FQDNProxyDenyWithNameError, FQDNProxyDenyWithRefused}

	// MonitorAggregationFlagsDefault ensure that all TCP flags trigger
	// monitor notifications even under medium monitor aggregation.
	MonitorAggregationFlagsDefault = []string{"syn", "fin", "rst"}
)

// Available option for DaemonConfig.Tunnel
const (
	// TunnelVXLAN specifies VXLAN encapsulation
	TunnelVXLAN = "vxlan"

	// TunnelGeneve specifies Geneve encapsulation
	TunnelGeneve = "geneve"

	// TunnelDisabled specifies to disable encapsulation
	TunnelDisabled = "disabled"
)

// Envoy option names
const (
	// HTTPNormalizePath switches on Envoy HTTP path normalization options, which currently
	// includes RFC 3986 path normalization, Envoy merge slashes option, and unescaping and
	// redirecting for paths that contain escaped slashes. These are necessary to keep path based
	// access control functional, and should not interfere with normal operation. Set this to
	// false only with caution.
	HTTPNormalizePath = "http-normalize-path"

	// HTTP403Message specifies the response body for 403 responses, defaults to "Access denied"
	HTTP403Message = "http-403-msg"

	// HTTPRequestTimeout specifies the time in seconds after which forwarded requests time out
	HTTPRequestTimeout = "http-request-timeout"

	// HTTPIdleTimeout spcifies the time in seconds if http stream being idle after which the
	// request times out
	HTTPIdleTimeout = "http-idle-timeout"

	// HTTPMaxGRPCTimeout specifies the maximum time in seconds that limits the values of
	// "grpc-timeout" headers being honored.
	HTTPMaxGRPCTimeout = "http-max-grpc-timeout"

	// HTTPRetryCount specifies the number of retries performed after a forwarded request fails
	HTTPRetryCount = "http-retry-count"

	// HTTPRetryTimeout is the time in seconds before an uncompleted request is retried.
	HTTPRetryTimeout = "http-retry-timeout"

	// ProxyConnectTimeout specifies the time in seconds after which a TCP connection attempt
	// is considered timed out
	ProxyConnectTimeout = "proxy-connect-timeout"

	// ProxyGID specifies the group ID that has access to unix domain sockets opened by Cilium
	// agent for proxy configuration and access logging.
	ProxyGID = "proxy-gid"

	// ReadCNIConfiguration reads the CNI configuration file and extracts
	// Cilium relevant information. This can be used to pass per node
	// configuration to Cilium.
	ReadCNIConfiguration = "read-cni-conf"

	// WriteCNIConfigurationWhenReady writes the CNI configuration to the
	// specified location once the agent is ready to serve requests. This
	// allows to keep a Kubernetes node NotReady until Cilium is up and
	// running and able to schedule endpoints.
	WriteCNIConfigurationWhenReady = "write-cni-conf-when-ready"

	// EnableCiliumEndpointSlice enables the cilium endpoint slicing feature.
	EnableCiliumEndpointSlice = "enable-cilium-endpoint-slice"
)

const (
	// NodePortMinDefault is the minimal port to listen for NodePort requests
	NodePortMinDefault = 30000

	// NodePortMaxDefault is the maximum port to listen for NodePort requests
	NodePortMaxDefault = 32767

	// NodePortModeSNAT is for SNATing requests to remote nodes
	NodePortModeSNAT = "snat"

	// NodePortModeDSR is for performing DSR for requests to remote nodes
	NodePortModeDSR = "dsr"

	// NodePortAlgRandom is for randomly selecting a backend
	NodePortAlgRandom = "random"

	// NodePortAlgMaglev is for using maglev consistent hashing for backend selection
	NodePortAlgMaglev = "maglev"

	// NodePortModeHybrid is a dual mode of the above, that is, DSR for TCP and SNAT for UDP
	NodePortModeHybrid = "hybrid"

	// DSR dispatch mode to encode service into IP option or extension header
	DSRDispatchOption = "opt"

	// DSR dispatch mode to encapsulate to IPIP
	DSRDispatchIPIP = "ipip"

	// DSR L4 translation to frontend port
	DSRL4XlateFrontend = "frontend"

	// DSR L4 translation to backend port
	DSRL4XlateBackend = "backend"

	// NodePortAccelerationDisabled means we do not accelerate NodePort via XDP
	NodePortAccelerationDisabled = XDPModeDisabled

	// NodePortAccelerationGeneric means we accelerate NodePort via generic XDP
	NodePortAccelerationGeneric = XDPModeGeneric

	// NodePortAccelerationNative means we accelerate NodePort via native XDP in the driver (preferred)
	NodePortAccelerationNative = XDPModeNative

	// KubeProxyReplacementProbe specifies to auto-enable available features for
	// kube-proxy replacement
	KubeProxyReplacementProbe = "probe"

	// KubeProxyReplacementPartial specifies to enable only selected kube-proxy
	// replacement features (might panic)
	KubeProxyReplacementPartial = "partial"

	// KubeProxyReplacementStrict specifies to enable all kube-proxy replacement
	// features (might panic)
	KubeProxyReplacementStrict = "strict"

	// KubeProxyReplacementDisabled specified to completely disable kube-proxy
	// replacement
	KubeProxyReplacementDisabled = "disabled"

	// KubeProxyReplacement healthz server bind address
	KubeProxyReplacementHealthzBindAddr = "kube-proxy-replacement-healthz-bind-address"
)

// GetTunnelModes returns the list of all tunnel modes
func GetTunnelModes() string {
	return fmt.Sprintf("%s, %s, %s", TunnelVXLAN, TunnelGeneve, TunnelDisabled)
}

// getEnvName returns the environment variable to be used for the given option name.
func getEnvName(option string) string {
	under := strings.Replace(option, "-", "_", -1)
	upper := strings.ToUpper(under)
	return ciliumEnvPrefix + upper
}

// RegisteredOptions maps all options that are bind to viper.
var RegisteredOptions = map[string]struct{}{}

// BindEnv binds the option name with an deterministic generated environment
// variable which s based on the given optName. If the same optName is bind
// more than 1 time, this function panics.
func BindEnv(optName string) {
	registerOpt(optName)
	viper.BindEnv(optName, getEnvName(optName))
}

// BindEnvWithLegacyEnvFallback binds the given option name with either the same
// environment variable as BindEnv, if it's set, or with the given legacyEnvName.
//
// The function is used to work around the viper.BindEnv limitation that only
// one environment variable can be bound for an option, and we need multiple
// environment variables due to backward compatibility reasons.
func BindEnvWithLegacyEnvFallback(optName, legacyEnvName string) {
	registerOpt(optName)

	envName := getEnvName(optName)
	if os.Getenv(envName) == "" {
		envName = legacyEnvName
	}

	viper.BindEnv(optName, envName)
}

func registerOpt(optName string) {
	_, ok := RegisteredOptions[optName]
	if ok || optName == "" {
		panic(fmt.Errorf("option already registered: %s", optName))
	}
	RegisteredOptions[optName] = struct{}{}
}

// LogRegisteredOptions logs all options that where bind to viper.
func LogRegisteredOptions(entry *logrus.Entry) {
	keys := make([]string, 0, len(RegisteredOptions))
	for k := range RegisteredOptions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := viper.GetStringSlice(k)
		if len(v) > 0 {
			entry.Infof("  --%s='%s'", k, strings.Join(v, ","))
		} else {
			entry.Infof("  --%s='%s'", k, viper.GetString(k))
		}
	}
}

// IpvlanConfig is the configuration used by Daemon when in ipvlan mode.
type IpvlanConfig struct {
	MasterDeviceIndex int
	OperationMode     string
}

// DaemonConfig is the configuration used by Daemon.
type DaemonConfig struct {
	CreationTime        time.Time
	BpfDir              string   // BPF template files directory
	LibDir              string   // Cilium library files directory
	RunDir              string   // Cilium runtime directory
	Devices             []string // bpf_host device
	DirectRoutingDevice string   // Direct routing device (used by BPF NodePort and BPF Host Routing)
	LBDevInheritIPAddr  string   // Device which IP addr used by bpf_host devices
	EnableXDPPrefilter  bool     // Enable XDP-based prefiltering
	DevicePreFilter     string   // Prefilter device
	ModePreFilter       string   // Prefilter mode
	XDPMode             string   // XDP mode, values: { xdpdrv | xdpgeneric | none }
	HostV4Addr          net.IP   // Host v4 address of the snooping device
	HostV6Addr          net.IP   // Host v6 address of the snooping device
	EncryptInterface    []string // Set of network facing interface to encrypt over
	EncryptNode         bool     // Set to true for encrypting node IP traffic

	Ipvlan IpvlanConfig // Ipvlan related configuration

	DatapathMode string // Datapath mode
	Tunnel       string // Tunnel mode
	TunnelPort   int    // Tunnel port

	DryMode bool // Do not create BPF maps, devices, ..

	// RestoreState enables restoring the state from previous running daemons.
	RestoreState bool

	// EnableHostIPRestore enables restoring the host IPs based on state
	// left behind by previous Cilium runs.
	EnableHostIPRestore bool

	KeepConfig bool // Keep configuration of existing endpoints when starting up.

	// AllowLocalhost defines when to allows the local stack to local endpoints
	// values: { auto | always | policy }
	AllowLocalhost string

	// StateDir is the directory where runtime state of endpoints is stored
	StateDir string

	// Options changeable at runtime
	Opts *IntOptions

	// Mutex for serializing configuration updates to the daemon.
	ConfigPatchMutex lock.RWMutex

	// Monitor contains the configuration for the node monitor.
	Monitor *models.MonitorStatus

	// AgentHealthPort is the TCP port for agent health status API
	AgentHealthPort int

	// ClusterHealthPort is the TCP port for cluster-wide network connectivity health API
	ClusterHealthPort int

	// ClusterMeshHealthPort is the TCP port for ClusterMesh apiserver health API
	ClusterMeshHealthPort int

	// AgentLabels contains additional labels to identify this agent in monitor events.
	AgentLabels []string

	// IPv6ClusterAllocCIDR is the base CIDR used to allocate IPv6 node
	// CIDRs if allocation is not performed by an orchestration system
	IPv6ClusterAllocCIDR string

	// IPv6ClusterAllocCIDRBase is derived from IPv6ClusterAllocCIDR and
	// contains the CIDR without the mask, e.g. "fdfd::1/64" -> "fdfd::"
	//
	// This variable should never be written to, it is initialized via
	// DaemonConfig.Validate()
	IPv6ClusterAllocCIDRBase string

	// K8sRequireIPv4PodCIDR requires the k8s node resource to specify the
	// IPv4 PodCIDR. Cilium will block bootstrapping until the information
	// is available.
	K8sRequireIPv4PodCIDR bool

	// K8sRequireIPv6PodCIDR requires the k8s node resource to specify the
	// IPv6 PodCIDR. Cilium will block bootstrapping until the information
	// is available.
	K8sRequireIPv6PodCIDR bool

	// K8sServiceCacheSize is the service cache size for cilium k8s package.
	K8sServiceCacheSize uint

	// MTU is the maximum transmission unit of the underlying network
	MTU int

	// RouteMetric is the metric used for the routes added to the cilium_host device
	RouteMetric int

	// ClusterName is the name of the cluster
	ClusterName string

	// ClusterID is the unique identifier of the cluster
	ClusterID int

	// ClusterMeshConfig is the path to the clustermesh configuration directory
	ClusterMeshConfig string

	// CTMapEntriesGlobalTCP is the maximum number of conntrack entries
	// allowed in each TCP CT table for IPv4/IPv6.
	CTMapEntriesGlobalTCP int

	// CTMapEntriesGlobalAny is the maximum number of conntrack entries
	// allowed in each non-TCP CT table for IPv4/IPv6.
	CTMapEntriesGlobalAny int

	// CTMapEntriesTimeout* values configured by the user.
	CTMapEntriesTimeoutTCP    time.Duration
	CTMapEntriesTimeoutAny    time.Duration
	CTMapEntriesTimeoutSVCTCP time.Duration
	CTMapEntriesTimeoutSVCAny time.Duration
	CTMapEntriesTimeoutSYN    time.Duration
	CTMapEntriesTimeoutFIN    time.Duration

	// EnableMonitor enables the monitor unix domain socket server
	EnableMonitor bool

	// MonitorAggregationInterval configures the interval between monitor
	// messages when monitor aggregation is enabled.
	MonitorAggregationInterval time.Duration

	// MonitorAggregationFlags determines which TCP flags that the monitor
	// aggregation ensures reports are generated for when monitor-aggragation
	// is enabled. Network byte-order.
	MonitorAggregationFlags uint16

	// BPFMapsDynamicSizeRatio is ratio of total system memory to use for
	// dynamic sizing of the CT, NAT, Neighbor and SockRevNAT BPF maps.
	BPFMapsDynamicSizeRatio float64

	// NATMapEntriesGlobal is the maximum number of NAT mappings allowed
	// in the BPF NAT table
	NATMapEntriesGlobal int

	// NeighMapEntriesGlobal is the maximum number of neighbor mappings
	// allowed in the BPF neigh table
	NeighMapEntriesGlobal int

	// PolicyMapEntries is the maximum number of peer identities that an
	// endpoint may allow traffic to exchange traffic with.
	PolicyMapEntries int

	// SockRevNatEntries is the maximum number of sock rev nat mappings
	// allowed in the BPF rev nat table
	SockRevNatEntries int

	// DisableCiliumEndpointCRD disables the use of CiliumEndpoint CRD
	DisableCiliumEndpointCRD bool

	// MaxControllerInterval is the maximum value for a controller's
	// RunInterval. Zero means unlimited.
	MaxControllerInterval int

	// UseSingleClusterRoute specifies whether to use a single cluster route
	// instead of per-node routes.
	UseSingleClusterRoute bool

	// HTTPNormalizePath switches on Envoy HTTP path normalization options, which currently
	// includes RFC 3986 path normalization, Envoy merge slashes option, and unescaping and
	// redirecting for paths that contain escaped slashes. These are necessary to keep path based
	// access control functional, and should not interfere with normal operation. Set this to
	// false only with caution.
	HTTPNormalizePath bool

	// HTTP403Message is the error message to return when a HTTP 403 is returned
	// by the proxy, if L7 policy is configured.
	HTTP403Message string

	// HTTPRequestTimeout is the time in seconds after which Envoy responds with an
	// error code on a request that has not yet completed. This needs to be longer
	// than the HTTPIdleTimeout
	HTTPRequestTimeout int

	// HTTPIdleTimeout is the time in seconds of a HTTP stream having no traffic after
	// which Envoy responds with an error code. This needs to be shorter than the
	// HTTPRequestTimeout
	HTTPIdleTimeout int

	// HTTPMaxGRPCTimeout is the upper limit to which "grpc-timeout" headers in GRPC
	// requests are honored by Envoy. If 0 there is no limit. GRPC requests are not
	// bound by the HTTPRequestTimeout, but ARE affected by the idle timeout!
	HTTPMaxGRPCTimeout int

	// HTTPRetryCount is the upper limit on how many times Envoy retries failed requests.
	HTTPRetryCount int

	// HTTPRetryTimeout is the time in seconds before an uncompleted request is retried.
	HTTPRetryTimeout int

	// ProxyConnectTimeout is the time in seconds after which Envoy considers a TCP
	// connection attempt to have timed out.
	ProxyConnectTimeout int

	// ProxyGID specifies the group ID that has access to unix domain sockets opened by Cilium
	// agent for proxy configuration and access logging.
	ProxyGID int

	// ProxyPrometheusPort specifies the port to serve Envoy metrics on.
	ProxyPrometheusPort int

	// ProxyMaxRequestsPerConnection specifies the max_requests_per_connection setting for the proxy
	ProxyMaxRequestsPerConnection int

	// ProxyMaxConnectionDuration specifies the max_connection_duration setting for the proxy
	ProxyMaxConnectionDuration time.Duration

	// EnvoyLogPath specifies where to store the Envoy proxy logs when Envoy
	// runs in the same container as Cilium.
	EnvoyLogPath string

	// EnableSockOps specifies whether to enable sockops (socket lookup).
	SockopsEnable bool

	ProcFs string

	// PrependIptablesChains is the name of the option to enable prepending
	// iptables chains instead of appending
	PrependIptablesChains bool

	// IPTablesLockTimeout defines the "-w" iptables option when the
	// iptables CLI is directly invoked from the Cilium agent.
	IPTablesLockTimeout time.Duration

	// IPTablesRandomFully defines the "--random-fully" iptables option when the
	// iptables CLI is directly invoked from the Cilium agent.
	IPTablesRandomFully bool

	// K8sNamespace is the name of the namespace in which Cilium is
	// deployed in when running in Kubernetes mode
	K8sNamespace string

	// JoinCluster is 'true' if the agent should join a Cilium cluster via kvstore
	// registration
	JoinCluster bool

	// EnableIPv4 is true when IPv4 is enabled
	EnableIPv4 bool

	// EnableIPv6 is true when IPv6 is enabled
	EnableIPv6 bool

	// EnableIPv6NDP is true when NDP is enabled for IPv6
	EnableIPv6NDP bool

	// IPv6MCastDevice is the name of device that joins IPv6's solicitation multicast group
	IPv6MCastDevice string

	// EnableL7Proxy is the option to enable L7 proxy
	EnableL7Proxy bool

	// EnableIPSec is true when IPSec is enabled
	EnableIPSec bool

	// IPSec key file for stored keys
	IPSecKeyFile string

	// EnableWireguard enables Wireguard encryption
	EnableWireguard bool

	// EnableWireguardUserspaceFallback enables the fallback to the userspace implementation
	EnableWireguardUserspaceFallback bool

	// MonitorQueueSize is the size of the monitor event queue
	MonitorQueueSize int

	// CLI options

	BPFRoot                       string
	BPFSocketLBHostnsOnly         bool
	CGroupRoot                    string
	BPFCompileDebug               string
	CompilerFlags                 []string
	ConfigFile                    string
	ConfigDir                     string
	Debug                         bool
	DebugVerbose                  []string
	EnableHostReachableServices   bool
	EnableHostServicesTCP         bool
	EnableHostServicesUDP         bool
	EnableHostServicesPeer        bool
	EnablePolicy                  string
	EnableTracing                 bool
	EnableUnreachableRoutes       bool
	EnvoyLog                      string
	DisableEnvoyVersionCheck      bool
	FixedIdentityMapping          map[string]string
	FixedIdentityMappingValidator func(val string) (string, error) `json:"-"`
	IPv4Range                     string
	IPv6Range                     string
	IPv4ServiceRange              string
	IPv6ServiceRange              string
	IpvlanMasterDevice            string
	K8sAPIServer                  string
	K8sKubeConfigPath             string
	K8sClientBurst                int
	K8sClientQPSLimit             float64
	K8sSyncTimeout                time.Duration
	AllocatorListTimeout          time.Duration
	K8sWatcherEndpointSelector    string
	KVStore                       string
	KVStoreOpt                    map[string]string
	LabelPrefixFile               string
	Labels                        []string
	LogDriver                     []string
	LogOpt                        map[string]string
	Logstash                      bool
	LogSystemLoadConfig           bool

	// Masquerade specifies whether or not to masquerade packets from endpoints
	// leaving the host.
	EnableIPv4Masquerade       bool
	EnableIPv6Masquerade       bool
	EnableBPFMasquerade        bool
	DeriveMasqIPAddrFromDevice string
	EnableBPFClockProbe        bool
	EnableIPMasqAgent          bool
	EnableIPv4EgressGateway    bool
	EnableEnvoyConfig          bool
	EnvoyConfigTimeout         time.Duration
	IPMasqAgentConfigPath      string
	InstallIptRules            bool
	MonitorAggregation         string
	PreAllocateMaps            bool
	IPv6NodeAddr               string
	IPv4NodeAddr               string
	SidecarIstioProxyImage     string
	SocketPath                 string
	TracePayloadlen            int
	Version                    string
	PProf                      bool
	PProfPort                  int
	PrometheusServeAddr        string
	ToFQDNsMinTTL              int

	// DNSMaxIPsPerRestoredRule defines the maximum number of IPs to maintain
	// for each FQDN selector in endpoint's restored DNS rules
	DNSMaxIPsPerRestoredRule int

	// DNSPolicyUnloadOnShutdown defines whether DNS policy rules should be unloaded on
	// graceful shutdown.
	DNSPolicyUnloadOnShutdown bool

	// ToFQDNsProxyPort is the user-configured global, shared, DNS listen port used
	// by the DNS Proxy. Both UDP and TCP are handled on the same port. When it
	// is 0 a random port will be assigned, and can be obtained from
	// DefaultDNSProxy below.
	ToFQDNsProxyPort int

	// ToFQDNsMaxIPsPerHost defines the maximum number of IPs to maintain
	// for each FQDN name in an endpoint's FQDN cache
	ToFQDNsMaxIPsPerHost int

	// ToFQDNsMaxIPsPerHost defines the maximum number of IPs to retain for
	// expired DNS lookups with still-active connections
	ToFQDNsMaxDeferredConnectionDeletes int

	// ToFQDNsIdleConnectionGracePeriod Time during which idle but
	// previously active connections with expired DNS lookups are
	// still considered alive
	ToFQDNsIdleConnectionGracePeriod time.Duration

	// FQDNRejectResponse is the dns-proxy response for invalid dns-proxy request
	FQDNRejectResponse string

	// FQDNProxyResponseMaxDelay The maximum time the DNS proxy holds an allowed
	// DNS response before sending it along. Responses are sent as soon as the
	// datapath is updated with the new IP information.
	FQDNProxyResponseMaxDelay time.Duration

	// Path to a file with DNS cache data to preload on startup
	ToFQDNsPreCache string

	// ToFQDNsEnableDNSCompression allows the DNS proxy to compress responses to
	// endpoints that are larger than 512 Bytes or the EDNS0 option, if present.
	ToFQDNsEnableDNSCompression bool

	// EnableXTSocketFallback allows disabling of kernel's ip_early_demux
	// sysctl option if `xt_socket` kernel module is not available.
	EnableXTSocketFallback bool

	// EnableBPFTProxy enables implementing proxy redirection via BPF
	// mechanisms rather than iptables rules.
	EnableBPFTProxy bool

	// EnableAutoDirectRouting enables installation of direct routes to
	// other nodes when available
	EnableAutoDirectRouting bool

	// EnableLocalNodeRoute controls installation of the route which points
	// the allocation prefix of the local node.
	EnableLocalNodeRoute bool

	// EnableHealthChecking enables health checking between nodes and
	// health endpoints
	EnableHealthChecking bool

	// EnableEndpointHealthChecking enables health checking between virtual
	// health endpoints
	EnableEndpointHealthChecking bool

	// EnableHealthCheckNodePort enables health checking of NodePort by
	// cilium
	EnableHealthCheckNodePort bool

	// KVstoreKeepAliveInterval is the interval in which the lease is being
	// renewed. This must be set to a value lesser than the LeaseTTL ideally
	// by a factor of 3.
	KVstoreKeepAliveInterval time.Duration

	// KVstoreLeaseTTL is the time-to-live for kvstore lease.
	KVstoreLeaseTTL time.Duration

	// KVstoreMaxConsecutiveQuorumErrors is the maximum number of acceptable
	// kvstore consecutive quorum errors before the agent assumes permanent failure
	KVstoreMaxConsecutiveQuorumErrors int

	// KVstorePeriodicSync is the time interval in which periodic
	// synchronization with the kvstore occurs
	KVstorePeriodicSync time.Duration

	// KVstoreConnectivityTimeout is the timeout when performing kvstore operations
	KVstoreConnectivityTimeout time.Duration

	// IPAllocationTimeout is the timeout when allocating CIDRs
	IPAllocationTimeout time.Duration

	// IdentityChangeGracePeriod is the grace period that needs to pass
	// before an endpoint that has changed its identity will start using
	// that new identity. During the grace period, the new identity has
	// already been allocated and other nodes in the cluster have a chance
	// to whitelist the new upcoming identity of the endpoint.
	IdentityChangeGracePeriod time.Duration

	// IdentityRestoreGracePeriod is the grace period that needs to pass before CIDR identities
	// restored during agent restart are released. If any of the restored identities remains
	// unused after this time, they will be removed from the IP cache. Any of the restored
	// identities that are used in network policies will remain in the IP cache until all such
	// policies are removed.
	IdentityRestoreGracePeriod time.Duration

	// PolicyQueueSize is the size of the queues for the policy repository.
	// A larger queue means that more events related to policy can be buffered.
	PolicyQueueSize int

	// EndpointQueueSize is the size of the EventQueue per-endpoint. A larger
	// queue means that more events can be buffered per-endpoint. This is useful
	// in the case where a cluster might be under high load for endpoint-related
	// events, specifically those which cause many regenerations.
	EndpointQueueSize int

	// EndpointGCInterval is interval to attempt garbage collection of
	// endpoints that are no longer alive and healthy.
	EndpointGCInterval time.Duration

	// SelectiveRegeneration, when true, enables the functionality to only
	// regenerate endpoints which are selected by the policy rules that have
	// been changed (added, deleted, or updated). If false, then all endpoints
	// are regenerated upon every policy change regardless of the scope of the
	// policy change.
	SelectiveRegeneration bool

	// ConntrackGCInterval is the connection tracking garbage collection
	// interval
	ConntrackGCInterval time.Duration

	// K8sEventHandover enables use of the kvstore to optimize Kubernetes
	// event handling by listening for k8s events in the operator and
	// mirroring it into the kvstore for reduced overhead in large
	// clusters.
	K8sEventHandover bool

	// MetricsConfig is the configuration set in metrics
	MetricsConfig metrics.Configuration

	// LoopbackIPv4 is the address to use for service loopback SNAT
	LoopbackIPv4 string

	// LocalRouterIPv4 is the link-local IPv4 address used for Cilium's router device
	LocalRouterIPv4 string

	// LocalRouterIPv6 is the link-local IPv6 address used for Cilium's router device
	LocalRouterIPv6 string

	// ForceLocalPolicyEvalAtSource forces a policy decision at the source
	// endpoint for all local communication
	ForceLocalPolicyEvalAtSource bool

	// EnableEndpointRoutes enables use of per endpoint routes
	EnableEndpointRoutes bool

	// Specifies wheather to annotate the kubernetes nodes or not
	AnnotateK8sNode bool

	// RunMonitorAgent indicates whether to run the monitor agent
	RunMonitorAgent bool

	// ReadCNIConfiguration reads the CNI configuration file and extracts
	// Cilium relevant information. This can be used to pass per node
	// configuration to Cilium.
	ReadCNIConfiguration string

	// WriteCNIConfigurationWhenReady writes the CNI configuration to the
	// specified location once the agent is ready to serve requests. This
	// allows to keep a Kubernetes node NotReady until Cilium is up and
	// running and able to schedule endpoints.
	WriteCNIConfigurationWhenReady string

	// EnableNodePort enables k8s NodePort service implementation in BPF
	EnableNodePort bool

	// EnableSVCSourceRangeCheck enables check of loadBalancerSourceRanges
	EnableSVCSourceRangeCheck bool

	// EnableHealthDatapath enables IPIP health probes data path
	EnableHealthDatapath bool

	// EnableHostPort enables k8s Pod's hostPort mapping through BPF
	EnableHostPort bool

	// EnableHostLegacyRouting enables the old routing path via stack.
	EnableHostLegacyRouting bool

	// NodePortNat46X64 indicates whether NAT46 / NAT64 can be used.
	NodePortNat46X64 bool

	// NodePortMode indicates in which mode NodePort implementation should run
	// ("snat", "dsr" or "hybrid")
	NodePortMode string

	// NodePortAlg indicates which backend selection algorithm is used
	// ("random" or "maglev")
	NodePortAlg string

	// LoadBalancerDSRDispatch indicates the method for pushing packets to
	// backends under DSR ("opt" or "ipip")
	LoadBalancerDSRDispatch string

	// LoadBalancerDSRL4Xlate indicates the method for L4 DNAT translation
	// under IPIP dispatch, that is, whether the inner packet will be
	// translated to the frontend or backend port.
	LoadBalancerDSRL4Xlate string

	// LoadBalancerRSSv4CIDR defines the outer source IPv4 prefix for DSR/IPIP
	LoadBalancerRSSv4CIDR string
	LoadBalancerRSSv4     net.IPNet

	// LoadBalancerRSSv4CIDR defines the outer source IPv6 prefix for DSR/IPIP
	LoadBalancerRSSv6CIDR string
	LoadBalancerRSSv6     net.IPNet

	// LoadBalancerPMTUDiscovery indicates whether LB should reply with ICMP
	// frag needed messages to client (when needed)
	LoadBalancerPMTUDiscovery bool

	// Maglev backend table size (M) per service. Must be prime number.
	MaglevTableSize int

	// MaglevHashSeed contains the cluster-wide seed for the hash(es).
	MaglevHashSeed string

	// NodePortAcceleration indicates whether NodePort should be accelerated
	// via XDP ("none", "generic" or "native")
	NodePortAcceleration string

	// NodePortBindProtection rejects bind requests to NodePort service ports
	NodePortBindProtection bool

	// EnableAutoProtectNodePortRange enables appending NodePort range to
	// net.ipv4.ip_local_reserved_ports if it overlaps with ephemeral port
	// range (net.ipv4.ip_local_port_range)
	EnableAutoProtectNodePortRange bool

	// KubeProxyReplacement controls how to enable kube-proxy replacement
	// features in BPF datapath
	KubeProxyReplacement string

	// EnableBandwidthManager enables EDT-based pacing
	EnableBandwidthManager bool

	// EnableBBR enables BBR TCP congestion control for the node including Pods
	EnableBBR bool

	// ResetQueueMapping resets the Pod's skb queue mapping
	ResetQueueMapping bool

	// EnableRecorder enables the datapath pcap recorder
	EnableRecorder bool

	// EnableMKE enables MKE specific 'chaining' for kube-proxy replacement
	EnableMKE bool

	// CgroupPathMKE points to the cgroupv1 net_cls mount instance
	CgroupPathMKE string

	// KubeProxyReplacementHealthzBindAddr is the KubeProxyReplacement healthz server bind addr
	KubeProxyReplacementHealthzBindAddr string

	// EnableExternalIPs enables implementation of k8s services with externalIPs in datapath
	EnableExternalIPs bool

	// EnableHostFirewall enables network policies for the host
	EnableHostFirewall bool

	// EnableLocalRedirectPolicy enables redirect policies to redirect traffic within nodes
	EnableLocalRedirectPolicy bool

	// K8sEnableEndpointSlice enables k8s endpoint slice feature that is used
	// in kubernetes.
	K8sEnableK8sEndpointSlice bool

	// NodePortMin is the minimum port address for the NodePort range
	NodePortMin int

	// NodePortMax is the maximum port address for the NodePort range
	NodePortMax int

	// EnableSessionAffinity enables a support for service sessionAffinity
	EnableSessionAffinity bool

	EnableServiceTopology bool

	// Selection of BPF main clock source (ktime vs jiffies)
	ClockSource BPFClockSource

	// EnableIdentityMark enables setting the mark field with the identity for
	// local traffic. This may be disabled if chaining modes and Cilium use
	// conflicting marks.
	EnableIdentityMark bool

	// KernelHz is the HZ rate the kernel is operating in
	KernelHz int

	// ExcludeLocalAddresses excludes certain addresses to be recognized as
	// a local address
	ExcludeLocalAddresses []*net.IPNet

	// IPv4PodSubnets available subnets to be assign IPv4 addresses to pods from
	IPv4PodSubnets []*net.IPNet

	// IPv6PodSubnets available subnets to be assign IPv6 addresses to pods from
	IPv6PodSubnets []*net.IPNet

	// IPAM is the IPAM method to use
	IPAM string

	// AutoCreateCiliumNodeResource enables automatic creation of a
	// CiliumNode resource for the local node
	AutoCreateCiliumNodeResource bool

	// IPv4NativeRoutingCIDR describes a CIDR in which pod IPs are routable
	IPv4NativeRoutingCIDR *cidr.CIDR

	// IPv6NativeRoutingCIDR describes a CIDR in which pod IPs are routable
	IPv6NativeRoutingCIDR *cidr.CIDR

	// EgressMasqueradeInterfaces is the selector used to select interfaces
	// subject to egress masquerading
	EgressMasqueradeInterfaces string

	// PolicyTriggerInterval is the amount of time between when policy updates
	// are triggered.
	PolicyTriggerInterval time.Duration

	// IdentityAllocationMode specifies what mode to use for identity
	// allocation
	IdentityAllocationMode string

	// DisableCNPStatusUpdates disables updating of CNP NodeStatus in the CNP
	// CRD.
	DisableCNPStatusUpdates bool

	// AllowICMPFragNeeded allows ICMP Fragmentation Needed type packets in
	// the network policy for cilium-agent.
	AllowICMPFragNeeded bool

	// EnableWellKnownIdentities enables the use of well-known identities.
	// This is requires if identiy resolution is required to bring up the
	// control plane, e.g. when using the managed etcd feature
	EnableWellKnownIdentities bool

	// CertsDirectory is the root directory to be used by cilium to find
	// certificates locally.
	CertDirectory string

	// EnableRemoteNodeIdentity enables use of the remote-node identity
	EnableRemoteNodeIdentity bool

	// Azure options

	// PolicyAuditMode enables non-drop mode for installed policies. In
	// audit mode packets affected by policies will not be dropped.
	// Policy related decisions can be checked via the poicy verdict messages.
	PolicyAuditMode bool

	// EnableHubble specifies whether to enable the hubble server.
	EnableHubble bool

	// HubbleSocketPath specifies the UNIX domain socket for Hubble server to listen to.
	HubbleSocketPath string

	// HubbleListenAddress specifies address for Hubble to listen to.
	HubbleListenAddress string

	// HubbleTLSDisabled allows the Hubble server to run on the given listen
	// address without TLS.
	HubbleTLSDisabled bool

	// HubbleTLSCertFile specifies the path to the public key file for the
	// Hubble server. The file must contain PEM encoded data.
	HubbleTLSCertFile string

	// HubbleTLSKeyFile specifies the path to the private key file for the
	// Hubble server. The file must contain PEM encoded data.
	HubbleTLSKeyFile string

	// HubbleTLSClientCAFiles specifies the path to one or more client CA
	// certificates to use for TLS with mutual authentication (mTLS). The files
	// must contain PEM encoded data.
	HubbleTLSClientCAFiles []string

	// HubbleEventBufferCapacity specifies the capacity of Hubble events buffer.
	HubbleEventBufferCapacity int

	// HubbleEventQueueSize specifies the buffer size of the channel to receive monitor events.
	HubbleEventQueueSize int

	// HubbleMetricsServer specifies the addresses to serve Hubble metrics on.
	HubbleMetricsServer string

	// HubbleMetrics specifies enabled metrics and their configuration options.
	HubbleMetrics []string

	// HubbleExportFilePath specifies the filepath to write Hubble events to.
	// e.g. "/var/run/cilium/hubble/events.log"
	HubbleExportFilePath string

	// HubbleExportFileMaxSizeMB specifies the file size in MB at which to rotate
	// the Hubble export file.
	HubbleExportFileMaxSizeMB int

	// HubbleExportFileMaxBacks specifies the number of rotated files to keep.
	HubbleExportFileMaxBackups int

	// HubbleExportFileCompress specifies whether rotated files are compressed.
	HubbleExportFileCompress bool

	// EnableHubbleRecorderAPI specifies if the Hubble Recorder API should be served
	EnableHubbleRecorderAPI bool

	// HubbleRecorderStoragePath specifies the directory in which pcap files
	// created via the Hubble Recorder API are stored
	HubbleRecorderStoragePath string

	// HubbleRecorderSinkQueueSize is the queue size for each recorder sink
	HubbleRecorderSinkQueueSize int

	// K8sHeartbeatTimeout configures the timeout for apiserver heartbeat
	K8sHeartbeatTimeout time.Duration

	// EndpointStatus enables population of information in the
	// CiliumEndpoint.Status resource
	EndpointStatus map[string]struct{}

	// DisableIptablesFeederRules specifies which chains will be excluded
	// when installing the feeder rules
	DisableIptablesFeederRules []string

	// EnableIPv4FragmentsTracking enables IPv4 fragments tracking for
	// L4-based lookups. Needs LRU map support.
	EnableIPv4FragmentsTracking bool

	// FragmentsMapEntries is the maximum number of fragmented datagrams
	// that can simultaneously be tracked in order to retrieve their L4
	// ports for all fragments.
	FragmentsMapEntries int

	// SizeofCTElement is the size of an element (key + value) in the CT map.
	SizeofCTElement int

	// SizeofNATElement is the size of an element (key + value) in the NAT map.
	SizeofNATElement int

	// SizeofNeighElement is the size of an element (key + value) in the neigh
	// map.
	SizeofNeighElement int

	// SizeofSockRevElement is the size of an element (key + value) in the neigh
	// map.
	SizeofSockRevElement int

	K8sEnableAPIDiscovery bool

	// k8sEnableLeasesFallbackDiscovery enables k8s to fallback to API probing to check
	// for the support of Leases in Kubernetes when there is an error in discovering
	// API groups using Discovery API.
	// We require to check for Leases capabilities in operator only, which uses Leases for leader
	// election purposes in HA mode.
	// This is only enabled for cilium-operator
	K8sEnableLeasesFallbackDiscovery bool

	// LBMapEntries is the maximum number of entries allowed in BPF lbmap.
	LBMapEntries int

	// LBServiceMapEntries is the maximum number of entries allowed in BPF lbmap for services.
	LBServiceMapEntries int

	// LBBackendMapEntries is the maximum number of entries allowed in BPF lbmap for service backends.
	LBBackendMapEntries int

	// LBRevNatEntries is the maximum number of entries allowed in BPF lbmap for reverse NAT.
	LBRevNatEntries int

	// LBAffinityMapEntries is the maximum number of entries allowed in BPF lbmap for session affinities.
	LBAffinityMapEntries int

	// LBSourceRangeMapEntries is the maximum number of entries allowed in BPF lbmap for source ranges.
	LBSourceRangeMapEntries int

	// LBMaglevMapEntries is the maximum number of entries allowed in BPF lbmap for maglev.
	LBMaglevMapEntries int

	// K8sServiceProxyName is the value of service.kubernetes.io/service-proxy-name label,
	// that identifies the service objects Cilium should handle.
	// If the provided value is an empty string, Cilium will manage service objects when
	// the label is not present. For more details -
	// https://github.com/kubernetes/enhancements/blob/master/keps/sig-network/0031-20181017-kube-proxy-services-optional.md
	K8sServiceProxyName string

	// APIRateLimitName enables configuration of the API rate limits
	APIRateLimit map[string]string

	// CRDWaitTimeout is the timeout in which Cilium will exit if CRDs are not
	// available.
	CRDWaitTimeout time.Duration

	// EgressMultiHomeIPRuleCompat instructs Cilium to use a new scheme to
	// store rules and routes under ENI and Azure IPAM modes, if false.
	// Otherwise, it will use the old scheme.
	EgressMultiHomeIPRuleCompat bool

	// InstallNoConntrackIptRules instructs Cilium to install Iptables rules to skip netfilter connection tracking on all pod traffic.
	InstallNoConntrackIptRules bool

	// EnableCustomCalls enables tail call hooks for user-defined custom
	// eBPF programs, typically used to collect custom per-endpoint
	// metrics.
	EnableCustomCalls bool

	// BGPAnnounceLBIP announces service IPs of type LoadBalancer via BGP.
	BGPAnnounceLBIP bool

	// BGPAnnouncePodCIDR announces the node's pod CIDR via BGP.
	BGPAnnouncePodCIDR bool

	// BGPConfigPath is the file path to the BGP configuration. It is
	// compatible with MetalLB's configuration.
	BGPConfigPath string

	// ExternalClusterIP enables routing to ClusterIP services from outside
	// the cluster. This mirrors the behaviour of kube-proxy.
	ExternalClusterIP bool

	// ARPPingRefreshPeriod is the ARP entries refresher period.
	ARPPingRefreshPeriod time.Duration
	// EnableCiliumEndpointSlice enables the cilium endpoint slicing feature.
	EnableCiliumEndpointSlice bool

	// ARPPingKernelManaged denotes whether kernel can auto-refresh Neighbor entries
	ARPPingKernelManaged bool

	// VLANBPFBypass list of explicitly allowed VLAN id's for bpf logic bypass
	VLANBPFBypass []int
	// EnableL2NeighDiscovery determines if cilium should perform L2 neighbor
	// discovery.
	EnableL2NeighDiscovery bool

	// EnableICMPRules enables ICMP-based rule support for Cilium Network Policies.
	EnableICMPRules bool

	// BypassIPAvailabilityUponRestore bypasses the IP availability error
	// within IPAM upon endpoint restore and allows the use of the restored IP
	// regardless of whether it's available in the pool.
	BypassIPAvailabilityUponRestore bool

	// EnableK8sTerminatingEndpoint enables auto-detect of terminating state for
	// Kubernetes service endpoints.
	EnableK8sTerminatingEndpoint bool

	// EnableVTEP enable Cilium VXLAN VTEP integration
	EnableVTEP bool

	// VtepEndpoints VTEP endpoint IPs
	VtepEndpoints []net.IP

	// VtepCIDRs VTEP CIDRs
	VtepCIDRs []*cidr.CIDR

	// VtepMask VTEP Mask
	VtepCidrMask net.IP

	// VtepMACs VTEP MACs
	VtepMACs []mac.MAC

	// TCFilterPriority sets the priority of the cilium tc filter, enabling other
	// filters to be inserted prior to the cilium filter.
	TCFilterPriority int

	// Enables BGP control plane features.
	EnableBGPControlPlane bool
}

var (
	// Config represents the daemon configuration
	Config = &DaemonConfig{
		CreationTime:                 time.Now(),
		Opts:                         NewIntOptions(&DaemonOptionLibrary),
		Monitor:                      &models.MonitorStatus{Cpus: int64(runtime.NumCPU()), Npages: 64, Pagesize: int64(os.Getpagesize()), Lost: 0, Unknown: 0},
		IPv6ClusterAllocCIDR:         defaults.IPv6ClusterAllocCIDR,
		IPv6ClusterAllocCIDRBase:     defaults.IPv6ClusterAllocCIDRBase,
		EnableHostIPRestore:          defaults.EnableHostIPRestore,
		EnableHealthChecking:         defaults.EnableHealthChecking,
		EnableEndpointHealthChecking: defaults.EnableEndpointHealthChecking,
		EnableHealthCheckNodePort:    defaults.EnableHealthCheckNodePort,
		EnableIPv4:                   defaults.EnableIPv4,
		EnableIPv6:                   defaults.EnableIPv6,
		EnableIPv6NDP:                defaults.EnableIPv6NDP,
		EnableL7Proxy:                defaults.EnableL7Proxy,
		EndpointStatus:               make(map[string]struct{}),
		DNSMaxIPsPerRestoredRule:     defaults.DNSMaxIPsPerRestoredRule,
		ToFQDNsMaxIPsPerHost:         defaults.ToFQDNsMaxIPsPerHost,
		KVstorePeriodicSync:          defaults.KVstorePeriodicSync,
		KVstoreConnectivityTimeout:   defaults.KVstoreConnectivityTimeout,
		IPAllocationTimeout:          defaults.IPAllocationTimeout,
		IdentityChangeGracePeriod:    defaults.IdentityChangeGracePeriod,
		IdentityRestoreGracePeriod:   defaults.IdentityRestoreGracePeriod,
		FixedIdentityMapping:         make(map[string]string),
		KVStoreOpt:                   make(map[string]string),
		LogOpt:                       make(map[string]string),
		SelectiveRegeneration:        defaults.SelectiveRegeneration,
		LoopbackIPv4:                 defaults.LoopbackIPv4,
		ForceLocalPolicyEvalAtSource: defaults.ForceLocalPolicyEvalAtSource,
		EnableEndpointRoutes:         defaults.EnableEndpointRoutes,
		AnnotateK8sNode:              defaults.AnnotateK8sNode,
		K8sServiceCacheSize:          defaults.K8sServiceCacheSize,
		AutoCreateCiliumNodeResource: defaults.AutoCreateCiliumNodeResource,
		IdentityAllocationMode:       IdentityAllocationModeKVstore,
		AllowICMPFragNeeded:          defaults.AllowICMPFragNeeded,
		EnableWellKnownIdentities:    defaults.EnableWellKnownIdentities,
		K8sEnableK8sEndpointSlice:    defaults.K8sEnableEndpointSlice,
		K8sEnableAPIDiscovery:        defaults.K8sEnableAPIDiscovery,
		AllocatorListTimeout:         defaults.AllocatorListTimeout,
		EnableICMPRules:              defaults.EnableICMPRules,

		K8sEnableLeasesFallbackDiscovery: defaults.K8sEnableLeasesFallbackDiscovery,
		APIRateLimit:                     make(map[string]string),

		ExternalClusterIP:     defaults.ExternalClusterIP,
		EnableVTEP:            defaults.EnableVTEP,
		EnableBGPControlPlane: defaults.EnableBGPControlPlane,
	}
)

// GetIPv4NativeRoutingCIDR returns the native routing CIDR if configured
func (c *DaemonConfig) GetIPv4NativeRoutingCIDR() (cidr *cidr.CIDR) {
	c.ConfigPatchMutex.RLock()
	cidr = c.IPv4NativeRoutingCIDR
	c.ConfigPatchMutex.RUnlock()
	return
}

// SetIPv4NativeRoutingCIDR sets the native routing CIDR
func (c *DaemonConfig) SetIPv4NativeRoutingCIDR(cidr *cidr.CIDR) {
	c.ConfigPatchMutex.Lock()
	c.IPv4NativeRoutingCIDR = cidr
	c.ConfigPatchMutex.Unlock()
}

// GetIPv6NativeRoutingCIDR returns the native routing CIDR if configured
func (c *DaemonConfig) GetIPv6NativeRoutingCIDR() (cidr *cidr.CIDR) {
	c.ConfigPatchMutex.RLock()
	cidr = c.IPv6NativeRoutingCIDR
	c.ConfigPatchMutex.RUnlock()
	return
}

// SetIPv6NativeRoutingCIDR sets the native routing CIDR
func (c *DaemonConfig) SetIPv6NativeRoutingCIDR(cidr *cidr.CIDR) {
	c.ConfigPatchMutex.Lock()
	c.IPv6NativeRoutingCIDR = cidr
	c.ConfigPatchMutex.Unlock()
}

// IsExcludedLocalAddress returns true if the specified IP matches one of the
// excluded local IP ranges
func (c *DaemonConfig) IsExcludedLocalAddress(ip net.IP) bool {
	for _, ipnet := range c.ExcludeLocalAddresses {
		if ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

// IsPodSubnetsDefined returns true if encryption subnets should be configured at init time.
func (c *DaemonConfig) IsPodSubnetsDefined() bool {
	return len(c.IPv4PodSubnets) > 0 || len(c.IPv6PodSubnets) > 0
}

// NodeConfigFile is the name of the C header which contains the node's
// network parameters.
const nodeConfigFile = "node_config.h"

// GetNodeConfigPath returns the full path of the NodeConfigFile.
func (c *DaemonConfig) GetNodeConfigPath() string {
	return filepath.Join(c.GetGlobalsDir(), nodeConfigFile)
}

// GetGlobalsDir returns the path for the globals directory.
func (c *DaemonConfig) GetGlobalsDir() string {
	return filepath.Join(c.StateDir, "globals")
}

// AlwaysAllowLocalhost returns true if the daemon has the option set that
// localhost can always reach local endpoints
func (c *DaemonConfig) AlwaysAllowLocalhost() bool {
	switch c.AllowLocalhost {
	case AllowLocalhostAlways:
		return true
	case AllowLocalhostAuto, AllowLocalhostPolicy:
		return false
	default:
		return false
	}
}

// TunnelingEnabled returns true if tunneling is enabled, i.e. not set to "disabled".
func (c *DaemonConfig) TunnelingEnabled() bool {
	return c.Tunnel != TunnelDisabled
}

// MasqueradingEnabled returns true if either IPv4 or IPv6 masquerading is enabled.
func (c *DaemonConfig) MasqueradingEnabled() bool {
	return c.EnableIPv4Masquerade || c.EnableIPv6Masquerade
}

// IptablesMasqueradingIPv4Enabled returns true if iptables-based
// masquerading is enabled for IPv4.
func (c *DaemonConfig) IptablesMasqueradingIPv4Enabled() bool {
	return !c.EnableBPFMasquerade && c.EnableIPv4Masquerade
}

// IptablesMasqueradingIPv6Enabled returns true if iptables-based
// masquerading is enabled for IPv6.
func (c *DaemonConfig) IptablesMasqueradingIPv6Enabled() bool {
	return !c.EnableBPFMasquerade && c.EnableIPv6Masquerade
}

// IptablesMasqueradingEnabled returns true if iptables-based
// masquerading is enabled.
func (c *DaemonConfig) IptablesMasqueradingEnabled() bool {
	return c.IptablesMasqueradingIPv4Enabled() || c.IptablesMasqueradingIPv6Enabled()
}

// NodeIpsetNeeded returns true if a node ipsets should be used to skip
// masquerading for traffic to cluster nodes.
func (c *DaemonConfig) NodeIpsetNeeded() bool {
	return c.Tunnel == TunnelDisabled && c.IptablesMasqueradingEnabled()
}

// RemoteNodeIdentitiesEnabled returns true if the remote-node identity feature
// is enabled
func (c *DaemonConfig) RemoteNodeIdentitiesEnabled() bool {
	return c.EnableRemoteNodeIdentity
}

// NodeEncryptionEnabled returns true if node encryption is enabled
func (c *DaemonConfig) NodeEncryptionEnabled() bool {
	return c.EncryptNode
}

// EncryptionEnabled returns true if encryption is enabled
func (c *DaemonConfig) EncryptionEnabled() bool {
	return c.EnableIPSec
}

// IPv4Enabled returns true if IPv4 is enabled
func (c *DaemonConfig) IPv4Enabled() bool {
	return c.EnableIPv4
}

// IPv6Enabled returns true if IPv6 is enabled
func (c *DaemonConfig) IPv6Enabled() bool {
	return c.EnableIPv6
}

// IPv6NDPEnabled returns true if IPv6 NDP support is enabled
func (c *DaemonConfig) IPv6NDPEnabled() bool {
	return c.EnableIPv6NDP
}

// HealthCheckingEnabled returns true if health checking is enabled
func (c *DaemonConfig) HealthCheckingEnabled() bool {
	return c.EnableHealthChecking
}

// IPAMMode returns the IPAM mode
func (c *DaemonConfig) IPAMMode() string {
	return strings.ToLower(c.IPAM)
}

// TracingEnabled returns if tracing policy (outlining which rules apply to a
// specific set of labels) is enabled.
func (c *DaemonConfig) TracingEnabled() bool {
	return c.Opts.IsEnabled(PolicyTracing)
}

// UnreachableRoutesEnabled returns true if unreachable routes is enabled
func (c *DaemonConfig) UnreachableRoutesEnabled() bool {
	return c.EnableUnreachableRoutes
}

// EndpointStatusIsEnabled returns true if a particular EndpointStatus* feature
// is enabled
func (c *DaemonConfig) EndpointStatusIsEnabled(option string) bool {
	_, ok := c.EndpointStatus[option]
	return ok
}

// LocalClusterName returns the name of the cluster Cilium is deployed in
func (c *DaemonConfig) LocalClusterName() string {
	return c.ClusterName
}

// K8sServiceProxyName returns the required value for the
// service.kubernetes.io/service-proxy-name label in order for services to be
// handled.
func (c *DaemonConfig) K8sServiceProxyNameValue() string {
	return c.K8sServiceProxyName
}

// CiliumNamespaceName returns the name of the namespace in which Cilium is
// deployed in
func (c *DaemonConfig) CiliumNamespaceName() string {
	return c.K8sNamespace
}

// K8sAPIDiscoveryEnabled returns true if API discovery of API groups and
// resources is enabled
func (c *DaemonConfig) K8sAPIDiscoveryEnabled() bool {
	return c.K8sEnableAPIDiscovery
}

// K8sLeasesFallbackDiscoveryEnabled returns true if we should fallback to direct API
// probing when checking for support of Leases in case Discovery API fails to discover
// required groups.
func (c *DaemonConfig) K8sLeasesFallbackDiscoveryEnabled() bool {
	return c.K8sEnableAPIDiscovery
}

// DirectRoutingDeviceRequired return whether the Direct Routing Device is needed under
// the current configuration.
func (c *DaemonConfig) DirectRoutingDeviceRequired() bool {
	// BPF NodePort and BPF Host Routing are using the direct routing device now.
	// When tunneling is enabled, node-to-node redirection will be done by tunneling.
	BPFHostRoutingEnabled := !c.EnableHostLegacyRouting
	return (c.EnableNodePort || BPFHostRoutingEnabled) && !c.TunnelingEnabled()
}

// EnableK8sLeasesFallbackDiscovery enables using direct API probing as a fallback to check
// for the support of Leases when discovering API groups is not possible.
func (c *DaemonConfig) EnableK8sLeasesFallbackDiscovery() {
	c.K8sEnableAPIDiscovery = true
}

func (c *DaemonConfig) validateIPv6ClusterAllocCIDR() error {
	ip, cidr, err := net.ParseCIDR(c.IPv6ClusterAllocCIDR)
	if err != nil {
		return err
	}

	if cidr == nil {
		return fmt.Errorf("ParseCIDR returned nil")
	}

	if ones, _ := cidr.Mask.Size(); ones != 64 {
		return fmt.Errorf("CIDR length must be /64")
	}

	c.IPv6ClusterAllocCIDRBase = ip.Mask(cidr.Mask).String()

	return nil
}

// Validate validates the daemon configuration
func (c *DaemonConfig) Validate() error {
	if err := c.validateIPv6ClusterAllocCIDR(); err != nil {
		return fmt.Errorf("unable to parse CIDR value '%s' of option --%s: %s",
			c.IPv6ClusterAllocCIDR, IPv6ClusterAllocCIDRName, err)
	}

	if c.MTU < 0 {
		return fmt.Errorf("MTU '%d' cannot be negative", c.MTU)
	}

	if c.RouteMetric < 0 {
		return fmt.Errorf("RouteMetric '%d' cannot be negative", c.RouteMetric)
	}

	if c.IPAM == ipamOption.IPAMENI && c.EnableIPv6 {
		return fmt.Errorf("IPv6 cannot be enabled in ENI IPAM mode")
	}

	if c.EnableIPv6NDP {
		if !c.EnableIPv6 {
			return fmt.Errorf("IPv6NDP cannot be enabled when IPv6 is not enabled")
		}
		if len(c.IPv6MCastDevice) == 0 && !MightAutoDetectDevices() {
			return fmt.Errorf("IPv6NDP cannot be enabled without %s", IPv6MCastDevice)
		}
	}

	switch c.Tunnel {
	case TunnelVXLAN, TunnelGeneve, "":
	case TunnelDisabled:
		if c.UseSingleClusterRoute {
			return fmt.Errorf("option --%s cannot be used in combination with --%s=%s",
				SingleClusterRouteName, TunnelName, TunnelDisabled)
		}
	default:
		return fmt.Errorf("invalid tunnel mode '%s', valid modes = {%s}", c.Tunnel, GetTunnelModes())
	}

	if c.ClusterID < clustermeshTypes.ClusterIDMin || c.ClusterID > clustermeshTypes.ClusterIDMax {
		return fmt.Errorf("invalid cluster id %d: must be in range %d..%d",
			c.ClusterID, clustermeshTypes.ClusterIDMin, clustermeshTypes.ClusterIDMax)
	}

	if c.ClusterID != 0 {
		if c.ClusterName == defaults.ClusterName {
			return fmt.Errorf("cannot use default cluster name (%s) with option %s",
				defaults.ClusterName, ClusterIDName)
		}
	}

	if err := c.checkMapSizeLimits(); err != nil {
		return err
	}

	if err := c.checkIPv4NativeRoutingCIDR(); err != nil {
		return err
	}

	if err := c.checkIPv6NativeRoutingCIDR(); err != nil {
		return err
	}

	// Validate that the KVStore Lease TTL value lies between a particular range.
	if c.KVstoreLeaseTTL > defaults.KVstoreLeaseMaxTTL || c.KVstoreLeaseTTL < defaults.LockLeaseTTL {
		return fmt.Errorf("KVstoreLeaseTTL does not lie in required range(%ds, %ds)",
			int64(defaults.LockLeaseTTL.Seconds()),
			int64(defaults.KVstoreLeaseMaxTTL.Seconds()))
	}

	if c.WriteCNIConfigurationWhenReady != "" && c.ReadCNIConfiguration == "" {
		return fmt.Errorf("%s must be set when using %s", ReadCNIConfiguration, WriteCNIConfigurationWhenReady)
	}

	if c.EnableHostReachableServices && !c.EnableHostServicesUDP && !c.EnableHostServicesTCP {
		return fmt.Errorf("%s must be at minimum one of [%s,%s]",
			HostReachableServicesProtos, HostServicesTCP, HostServicesUDP)
	}

	allowedEndpointStatusValues := EndpointStatusValuesMap()
	for enabledEndpointStatus := range c.EndpointStatus {
		if _, ok := allowedEndpointStatusValues[enabledEndpointStatus]; !ok {
			return fmt.Errorf("unknown endpoint-status option '%s'", enabledEndpointStatus)
		}
	}

	if c.EnableVTEP {
		err := c.validateVTEP()
		if err != nil {
			return fmt.Errorf("Failed to validate VTEP configuration: %w", err)
		}
	}

	return nil
}

// ReadDirConfig reads the given directory and returns a map that maps the
// filename to the contents of that file.
func ReadDirConfig(dirName string) (map[string]interface{}, error) {
	m := map[string]interface{}{}
	files, err := os.ReadDir(dirName)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to read configuration directory: %s", err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		fName := filepath.Join(dirName, f.Name())

		// the file can still be a symlink to a directory
		if f.Type()&os.ModeSymlink == 0 {
			absFileName, err := filepath.EvalSymlinks(fName)
			if err != nil {
				log.WithError(err).Warnf("Unable to read configuration file %q", absFileName)
				continue
			}
			fName = absFileName
		}

		fi, err := os.Stat(fName)
		if err != nil {
			log.WithError(err).Warnf("Unable to read configuration file %q", fName)
			continue
		}
		if fi.Mode().IsDir() {
			continue
		}

		b, err := os.ReadFile(fName)
		if err != nil {
			log.WithError(err).Warnf("Unable to read configuration file %q", fName)
			continue
		}
		m[f.Name()] = string(bytes.TrimSpace(b))
	}
	return m, nil
}

// MergeConfig merges the given configuration map with viper's configuration.
func MergeConfig(m map[string]interface{}) error {
	err := viper.MergeConfigMap(m)
	if err != nil {
		return fmt.Errorf("unable to read merge directory configuration: %s", err)
	}
	return nil
}

// ReplaceDeprecatedFields replaces the deprecated options set with the new set
// of options that overwrite the deprecated ones.
// This function replaces the deprecated fields used by environment variables
// with a different name than the option they are setting. This also replaces
// the deprecated names used in the Kubernetes ConfigMap.
// Once we remove them from this function we also need to remove them from
// daemon_main.go and warn users about the old environment variable nor the
// option in the configuration map have any effect.
func ReplaceDeprecatedFields(m map[string]interface{}) {
	deprecatedFields := map[string]string{
		"monitor-aggregation-level":   MonitorAggregationName,
		"ct-global-max-entries-tcp":   CTMapEntriesGlobalTCPName,
		"ct-global-max-entries-other": CTMapEntriesGlobalAnyName,
	}
	for deprecatedOption, newOption := range deprecatedFields {
		if deprecatedValue, ok := m[deprecatedOption]; ok {
			if _, ok := m[newOption]; !ok {
				m[newOption] = deprecatedValue
			}
		}
	}
}

func (c *DaemonConfig) parseExcludedLocalAddresses(s []string) error {
	for _, ipString := range s {
		_, ipnet, err := net.ParseCIDR(ipString)
		if err != nil {
			return fmt.Errorf("unable to parse excluded local address %s: %s", ipString, err)
		}

		c.ExcludeLocalAddresses = append(c.ExcludeLocalAddresses, ipnet)
	}

	return nil
}

// Populate sets all options with the values from viper
func (c *DaemonConfig) Populate() {
	var err error

	c.AgentHealthPort = viper.GetInt(AgentHealthPort)
	c.ClusterHealthPort = viper.GetInt(ClusterHealthPort)
	c.ClusterMeshHealthPort = viper.GetInt(ClusterMeshHealthPort)
	c.AgentLabels = viper.GetStringSlice(AgentLabels)
	c.AllowICMPFragNeeded = viper.GetBool(AllowICMPFragNeeded)
	c.AllowLocalhost = viper.GetString(AllowLocalhost)
	c.AnnotateK8sNode = viper.GetBool(AnnotateK8sNode)
	c.ARPPingRefreshPeriod = viper.GetDuration(ARPPingRefreshPeriod)
	c.EnableL2NeighDiscovery = viper.GetBool(EnableL2NeighDiscovery)
	c.AutoCreateCiliumNodeResource = viper.GetBool(AutoCreateCiliumNodeResource)
	c.BPFRoot = viper.GetString(BPFRoot)
	c.CertDirectory = viper.GetString(CertsDirectory)
	c.CGroupRoot = viper.GetString(CGroupRoot)
	c.ClusterID = viper.GetInt(ClusterIDName)
	c.ClusterName = viper.GetString(ClusterName)
	c.ClusterMeshConfig = viper.GetString(ClusterMeshConfigName)
	c.DatapathMode = viper.GetString(DatapathMode)
	c.Debug = viper.GetBool(DebugArg)
	c.DebugVerbose = viper.GetStringSlice(DebugVerbose)
	c.DirectRoutingDevice = viper.GetString(DirectRoutingDevice)
	c.LBDevInheritIPAddr = viper.GetString(LBDevInheritIPAddr)
	c.EnableIPv4 = viper.GetBool(EnableIPv4Name)
	c.EnableIPv6 = viper.GetBool(EnableIPv6Name)
	c.EnableIPv6NDP = viper.GetBool(EnableIPv6NDPName)
	c.IPv6MCastDevice = viper.GetString(IPv6MCastDevice)
	c.EnableIPSec = viper.GetBool(EnableIPSecName)
	c.EnableWireguard = viper.GetBool(EnableWireguard)
	c.EnableWireguardUserspaceFallback = viper.GetBool(EnableWireguardUserspaceFallback)
	c.EnableWellKnownIdentities = viper.GetBool(EnableWellKnownIdentities)
	c.EnableXDPPrefilter = viper.GetBool(EnableXDPPrefilter)
	c.DevicePreFilter = viper.GetString(PrefilterDevice)
	c.DisableCiliumEndpointCRD = viper.GetBool(DisableCiliumEndpointCRDName)
	c.EgressMasqueradeInterfaces = viper.GetString(EgressMasqueradeInterfaces)
	c.BPFSocketLBHostnsOnly = viper.GetBool(BPFSocketLBHostnsOnly)
	c.EnableHostReachableServices = viper.GetBool(EnableHostReachableServices)
	c.EnableRemoteNodeIdentity = viper.GetBool(EnableRemoteNodeIdentity)
	c.K8sHeartbeatTimeout = viper.GetDuration(K8sHeartbeatTimeout)
	c.EnableBPFTProxy = viper.GetBool(EnableBPFTProxy)
	c.EnableXTSocketFallback = viper.GetBool(EnableXTSocketFallbackName)
	c.EnableAutoDirectRouting = viper.GetBool(EnableAutoDirectRoutingName)
	c.EnableEndpointRoutes = viper.GetBool(EnableEndpointRoutes)
	c.EnableHealthChecking = viper.GetBool(EnableHealthChecking)
	c.EnableEndpointHealthChecking = viper.GetBool(EnableEndpointHealthChecking)
	c.EnableHealthCheckNodePort = viper.GetBool(EnableHealthCheckNodePort)
	c.EnableLocalNodeRoute = viper.GetBool(EnableLocalNodeRoute)
	c.EnablePolicy = strings.ToLower(viper.GetString(EnablePolicy))
	c.EnableExternalIPs = viper.GetBool(EnableExternalIPs)
	c.EnableL7Proxy = viper.GetBool(EnableL7Proxy)
	c.EnableTracing = viper.GetBool(EnableTracing)
	c.EnableUnreachableRoutes = viper.GetBool(EnableUnreachableRoutes)
	c.EnableNodePort = viper.GetBool(EnableNodePort)
	c.EnableSVCSourceRangeCheck = viper.GetBool(EnableSVCSourceRangeCheck)
	c.EnableHostPort = viper.GetBool(EnableHostPort)
	c.EnableHostLegacyRouting = viper.GetBool(EnableHostLegacyRouting)
	c.MaglevTableSize = viper.GetInt(MaglevTableSize)
	c.MaglevHashSeed = viper.GetString(MaglevHashSeed)
	c.NodePortBindProtection = viper.GetBool(NodePortBindProtection)
	c.EnableAutoProtectNodePortRange = viper.GetBool(EnableAutoProtectNodePortRange)
	c.KubeProxyReplacement = viper.GetString(KubeProxyReplacement)
	c.EnableSessionAffinity = viper.GetBool(EnableSessionAffinity)
	c.EnableServiceTopology = viper.GetBool(EnableServiceTopology)
	c.EnableBandwidthManager = viper.GetBool(EnableBandwidthManager)
	c.EnableBBR = viper.GetBool(EnableBBR)
	c.EnableRecorder = viper.GetBool(EnableRecorder)
	c.EnableMKE = viper.GetBool(EnableMKE)
	c.CgroupPathMKE = viper.GetString(CgroupPathMKE)
	c.EnableHostFirewall = viper.GetBool(EnableHostFirewall)
	c.EnableLocalRedirectPolicy = viper.GetBool(EnableLocalRedirectPolicy)
	c.EncryptInterface = viper.GetStringSlice(EncryptInterface)
	c.EncryptNode = viper.GetBool(EncryptNode)
	c.EnvoyLogPath = viper.GetString(EnvoyLog)
	c.ForceLocalPolicyEvalAtSource = viper.GetBool(ForceLocalPolicyEvalAtSource)
	c.HTTPNormalizePath = viper.GetBool(HTTPNormalizePath)
	c.HTTPIdleTimeout = viper.GetInt(HTTPIdleTimeout)
	c.HTTPMaxGRPCTimeout = viper.GetInt(HTTPMaxGRPCTimeout)
	c.HTTPRequestTimeout = viper.GetInt(HTTPRequestTimeout)
	c.HTTPRetryCount = viper.GetInt(HTTPRetryCount)
	c.HTTPRetryTimeout = viper.GetInt(HTTPRetryTimeout)
	c.IdentityChangeGracePeriod = viper.GetDuration(IdentityChangeGracePeriod)
	c.IdentityRestoreGracePeriod = viper.GetDuration(IdentityRestoreGracePeriod)
	c.IPAM = viper.GetString(IPAM)
	c.IPv4Range = viper.GetString(IPv4Range)
	c.IPv4NodeAddr = viper.GetString(IPv4NodeAddr)
	c.IPv4ServiceRange = viper.GetString(IPv4ServiceRange)
	c.IPv6ClusterAllocCIDR = viper.GetString(IPv6ClusterAllocCIDRName)
	c.IPv6NodeAddr = viper.GetString(IPv6NodeAddr)
	c.IPv6Range = viper.GetString(IPv6Range)
	c.IPv6ServiceRange = viper.GetString(IPv6ServiceRange)
	c.JoinCluster = viper.GetBool(JoinClusterName)
	c.K8sAPIServer = viper.GetString(K8sAPIServer)
	c.K8sClientBurst = viper.GetInt(K8sClientBurst)
	c.K8sClientQPSLimit = viper.GetFloat64(K8sClientQPSLimit)
	c.K8sEnableK8sEndpointSlice = viper.GetBool(K8sEnableEndpointSlice)
	c.K8sEnableAPIDiscovery = viper.GetBool(K8sEnableAPIDiscovery)
	c.K8sKubeConfigPath = viper.GetString(K8sKubeConfigPath)
	c.K8sRequireIPv4PodCIDR = viper.GetBool(K8sRequireIPv4PodCIDRName)
	c.K8sRequireIPv6PodCIDR = viper.GetBool(K8sRequireIPv6PodCIDRName)
	c.K8sServiceCacheSize = uint(viper.GetInt(K8sServiceCacheSize))
	c.K8sEventHandover = viper.GetBool(K8sEventHandover)
	c.K8sSyncTimeout = viper.GetDuration(K8sSyncTimeoutName)
	c.AllocatorListTimeout = viper.GetDuration(AllocatorListTimeoutName)
	c.K8sWatcherEndpointSelector = viper.GetString(K8sWatcherEndpointSelector)
	c.KeepConfig = viper.GetBool(KeepConfig)
	c.KVStore = viper.GetString(KVStore)
	c.KVstoreLeaseTTL = viper.GetDuration(KVstoreLeaseTTL)
	c.KVstoreKeepAliveInterval = c.KVstoreLeaseTTL / defaults.KVstoreKeepAliveIntervalFactor
	c.KVstorePeriodicSync = viper.GetDuration(KVstorePeriodicSync)
	c.KVstoreConnectivityTimeout = viper.GetDuration(KVstoreConnectivityTimeout)
	c.KVstoreMaxConsecutiveQuorumErrors = viper.GetInt(KVstoreMaxConsecutiveQuorumErrorsName)
	c.IPAllocationTimeout = viper.GetDuration(IPAllocationTimeout)
	c.LabelPrefixFile = viper.GetString(LabelPrefixFile)
	c.Labels = viper.GetStringSlice(Labels)
	c.LibDir = viper.GetString(LibDir)
	c.LogDriver = viper.GetStringSlice(LogDriver)
	c.LogSystemLoadConfig = viper.GetBool(LogSystemLoadConfigName)
	c.Logstash = viper.GetBool(Logstash)
	c.LoopbackIPv4 = viper.GetString(LoopbackIPv4)
	c.LocalRouterIPv4 = viper.GetString(LocalRouterIPv4)
	c.LocalRouterIPv6 = viper.GetString(LocalRouterIPv6)
	c.EnableBPFClockProbe = viper.GetBool(EnableBPFClockProbe)
	c.EnableIPMasqAgent = viper.GetBool(EnableIPMasqAgent)
	c.EnableIPv4EgressGateway = viper.GetBool(EnableIPv4EgressGateway)
	c.EnableEnvoyConfig = viper.GetBool(EnableEnvoyConfig)
	c.EnvoyConfigTimeout = viper.GetDuration(EnvoyConfigTimeout)
	c.IPMasqAgentConfigPath = viper.GetString(IPMasqAgentConfigPath)
	c.InstallIptRules = viper.GetBool(InstallIptRules)
	c.IPTablesLockTimeout = viper.GetDuration(IPTablesLockTimeout)
	c.IPTablesRandomFully = viper.GetBool(IPTablesRandomFully)
	c.IPSecKeyFile = viper.GetString(IPSecKeyFileName)
	c.IpvlanMasterDevice = viper.GetString(IpvlanMasterDevice)
	c.ModePreFilter = viper.GetString(PrefilterMode)
	c.EnableMonitor = viper.GetBool(EnableMonitorName)
	c.MonitorAggregation = viper.GetString(MonitorAggregationName)
	c.MonitorAggregationInterval = viper.GetDuration(MonitorAggregationInterval)
	c.MonitorQueueSize = viper.GetInt(MonitorQueueSizeName)
	c.MTU = viper.GetInt(MTUName)
	c.PProf = viper.GetBool(PProf)
	c.PProfPort = viper.GetInt(PProfPort)
	c.PreAllocateMaps = viper.GetBool(PreAllocateMapsName)
	c.PrependIptablesChains = viper.GetBool(PrependIptablesChainsName)
	c.ProcFs = viper.GetString(ProcFs)
	c.PrometheusServeAddr = viper.GetString(PrometheusServeAddr)
	c.ProxyConnectTimeout = viper.GetInt(ProxyConnectTimeout)
	c.ProxyGID = viper.GetInt(ProxyGID)
	c.ProxyPrometheusPort = viper.GetInt(ProxyPrometheusPort)
	c.ProxyMaxRequestsPerConnection = viper.GetInt(ProxyMaxRequestsPerConnection)
	c.ProxyMaxConnectionDuration = time.Duration(viper.GetInt64(ProxyMaxConnectionDuration))
	c.ReadCNIConfiguration = viper.GetString(ReadCNIConfiguration)
	c.RestoreState = viper.GetBool(Restore)
	c.RouteMetric = viper.GetInt(RouteMetric)
	c.RunDir = viper.GetString(StateDir)
	c.SidecarIstioProxyImage = viper.GetString(SidecarIstioProxyImage)
	c.UseSingleClusterRoute = viper.GetBool(SingleClusterRouteName)
	c.SocketPath = viper.GetString(SocketPath)
	c.SockopsEnable = viper.GetBool(SockopsEnableName)
	c.TracePayloadlen = viper.GetInt(TracePayloadlen)
	c.Version = viper.GetString(Version)
	c.WriteCNIConfigurationWhenReady = viper.GetString(WriteCNIConfigurationWhenReady)
	c.PolicyTriggerInterval = viper.GetDuration(PolicyTriggerInterval)
	c.CTMapEntriesTimeoutTCP = viper.GetDuration(CTMapEntriesTimeoutTCPName)
	c.CTMapEntriesTimeoutAny = viper.GetDuration(CTMapEntriesTimeoutAnyName)
	c.CTMapEntriesTimeoutSVCTCP = viper.GetDuration(CTMapEntriesTimeoutSVCTCPName)
	c.CTMapEntriesTimeoutSVCAny = viper.GetDuration(CTMapEntriesTimeoutSVCAnyName)
	c.CTMapEntriesTimeoutSYN = viper.GetDuration(CTMapEntriesTimeoutSYNName)
	c.CTMapEntriesTimeoutFIN = viper.GetDuration(CTMapEntriesTimeoutFINName)
	c.PolicyAuditMode = viper.GetBool(PolicyAuditModeArg)
	c.EnableIPv4FragmentsTracking = viper.GetBool(EnableIPv4FragmentsTrackingName)
	c.FragmentsMapEntries = viper.GetInt(FragmentsMapEntriesName)
	c.K8sServiceProxyName = viper.GetString(K8sServiceProxyName)
	c.CRDWaitTimeout = viper.GetDuration(CRDWaitTimeout)
	c.LoadBalancerDSRDispatch = viper.GetString(LoadBalancerDSRDispatch)
	c.LoadBalancerDSRL4Xlate = viper.GetString(LoadBalancerDSRL4Xlate)
	c.LoadBalancerRSSv4CIDR = viper.GetString(LoadBalancerRSSv4CIDR)
	c.LoadBalancerRSSv6CIDR = viper.GetString(LoadBalancerRSSv6CIDR)
	c.InstallNoConntrackIptRules = viper.GetBool(InstallNoConntrackIptRules)
	c.EnableCustomCalls = viper.GetBool(EnableCustomCallsName)
	c.BGPAnnounceLBIP = viper.GetBool(BGPAnnounceLBIP)
	c.BGPAnnouncePodCIDR = viper.GetBool(BGPAnnouncePodCIDR)
	c.BGPConfigPath = viper.GetString(BGPConfigPath)
	c.ExternalClusterIP = viper.GetBool(ExternalClusterIPName)
	c.TCFilterPriority = viper.GetInt(TCFilterPriority)

	c.EnableIPv4Masquerade = viper.GetBool(EnableIPv4Masquerade) && c.EnableIPv4
	c.EnableIPv6Masquerade = viper.GetBool(EnableIPv6Masquerade) && c.EnableIPv6
	c.EnableBPFMasquerade = viper.GetBool(EnableBPFMasquerade)
	c.DeriveMasqIPAddrFromDevice = viper.GetString(DeriveMasqIPAddrFromDevice)

	c.populateLoadBalancerSettings()
	c.populateDevices()
	c.EgressMultiHomeIPRuleCompat = viper.GetBool(EgressMultiHomeIPRuleCompat)

	c.VLANBPFBypass = viper.GetIntSlice(VLANBPFBypass)

	c.Tunnel = viper.GetString(TunnelName)
	c.TunnelPort = viper.GetInt(TunnelPortName)

	if c.TunnelPort == 0 {
		switch c.Tunnel {
		case TunnelVXLAN:
			c.TunnelPort = defaults.TunnelPortVXLAN
		case TunnelGeneve:
			c.TunnelPort = defaults.TunnelPortGeneve
		}
	}

	nativeRoutingCIDR := viper.GetString(NativeRoutingCIDR)
	ipv4NativeRoutingCIDR := viper.GetString(IPv4NativeRoutingCIDR)

	if nativeRoutingCIDR != "" && ipv4NativeRoutingCIDR != "" {
		log.Fatalf("Cannot specify both %s and %s", NativeRoutingCIDR, IPv4NativeRoutingCIDR)
	}

	if nativeRoutingCIDR != "" {
		c.IPv4NativeRoutingCIDR = cidr.MustParseCIDR(nativeRoutingCIDR)

		if len(c.IPv4NativeRoutingCIDR.IP) != net.IPv4len {
			log.Fatalf("%s must be an IPv4 CIDR", NativeRoutingCIDR)
		}
	} else if ipv4NativeRoutingCIDR != "" {
		c.IPv4NativeRoutingCIDR = cidr.MustParseCIDR(ipv4NativeRoutingCIDR)

		if len(c.IPv4NativeRoutingCIDR.IP) != net.IPv4len {
			log.Fatalf("%s must be an IPv4 CIDR", IPv4NativeRoutingCIDR)
		}
	}

	if c.EnableIPv4 && nativeRoutingCIDR == "" && ipv4NativeRoutingCIDR == "" && c.EnableAutoDirectRouting {
		log.Warnf("If %s is enabled, then you are recommended to also configure %s. If %s is not configured, this may lead to pod to pod traffic being masqueraded, "+
			"which can cause problems with performance, observability and policy", EnableAutoDirectRoutingName, IPv4NativeRoutingCIDR, IPv4NativeRoutingCIDR)
	}

	ipv6NativeRoutingCIDR := viper.GetString(IPv6NativeRoutingCIDR)

	if ipv6NativeRoutingCIDR != "" {
		c.IPv6NativeRoutingCIDR = cidr.MustParseCIDR(ipv6NativeRoutingCIDR)

		if len(c.IPv6NativeRoutingCIDR.IP) != net.IPv6len {
			log.Fatalf("%s must be an IPv6 CIDR", IPv6NativeRoutingCIDR)
		}
	}

	if c.EnableIPv6 && ipv6NativeRoutingCIDR == "" && c.EnableAutoDirectRouting {
		log.Warnf("If %s is enabled, then you are recommended to also configure %s. If %s is not configured, this may lead to pod to pod traffic being masqueraded, "+
			"which can cause problems with performance, observability and policy", EnableAutoDirectRoutingName, IPv6NativeRoutingCIDR, IPv6NativeRoutingCIDR)
	}

	if err := c.calculateBPFMapSizes(); err != nil {
		log.Fatal(err)
	}

	c.ClockSource = ClockSourceKtime
	c.EnableIdentityMark = viper.GetBool(EnableIdentityMark)

	// toFQDNs options
	c.DNSMaxIPsPerRestoredRule = viper.GetInt(DNSMaxIPsPerRestoredRule)
	c.DNSPolicyUnloadOnShutdown = viper.GetBool(DNSPolicyUnloadOnShutdown)
	c.ToFQDNsMaxIPsPerHost = viper.GetInt(ToFQDNsMaxIPsPerHost)
	if maxZombies := viper.GetInt(ToFQDNsMaxDeferredConnectionDeletes); maxZombies >= 0 {
		c.ToFQDNsMaxDeferredConnectionDeletes = viper.GetInt(ToFQDNsMaxDeferredConnectionDeletes)
	} else {
		log.Fatalf("%s must be positive, or 0 to disable deferred connection deletion",
			ToFQDNsMaxDeferredConnectionDeletes)
	}
	switch {
	case viper.IsSet(ToFQDNsMinTTL): // set by user
		c.ToFQDNsMinTTL = viper.GetInt(ToFQDNsMinTTL)
	default:
		c.ToFQDNsMinTTL = defaults.ToFQDNsMinTTL
	}
	c.ToFQDNsProxyPort = viper.GetInt(ToFQDNsProxyPort)
	c.ToFQDNsPreCache = viper.GetString(ToFQDNsPreCache)
	c.ToFQDNsEnableDNSCompression = viper.GetBool(ToFQDNsEnableDNSCompression)

	// Convert IP strings into net.IPNet types
	subnets, invalid := ip.ParseCIDRs(viper.GetStringSlice(IPv4PodSubnets))
	if len(invalid) > 0 {
		log.WithFields(
			logrus.Fields{
				"Subnets": invalid,
			}).Warning("IPv4PodSubnets parameter can not be parsed.")
	}
	c.IPv4PodSubnets = subnets

	subnets, invalid = ip.ParseCIDRs(viper.GetStringSlice(IPv6PodSubnets))
	if len(invalid) > 0 {
		log.WithFields(
			logrus.Fields{
				"Subnets": invalid,
			}).Warning("IPv6PodSubnets parameter can not be parsed.")
	}
	c.IPv6PodSubnets = subnets

	c.XDPMode = XDPModeLinkNone

	err = c.populateNodePortRange()
	if err != nil {
		log.WithError(err).Fatal("Failed to populate NodePortRange")
	}

	err = c.populateHostServicesProtos()
	if err != nil {
		log.WithError(err).Fatal("Failed to populate HostReachableServicesProtos")
	}

	monitorAggregationFlags := viper.GetStringSlice(MonitorAggregationFlags)
	var ctMonitorReportFlags uint16
	for i := 0; i < len(monitorAggregationFlags); i++ {
		value := strings.ToLower(monitorAggregationFlags[i])
		flag, exists := TCPFlags[value]
		if !exists {
			log.Fatalf("Unable to parse TCP flag %q for %s!",
				value, MonitorAggregationFlags)
		}
		ctMonitorReportFlags |= flag
	}
	c.MonitorAggregationFlags = ctMonitorReportFlags

	// Map options
	if m := command.GetStringMapString(viper.GetViper(), FixedIdentityMapping); err != nil {
		log.Fatalf("unable to parse %s: %s", FixedIdentityMapping, err)
	} else if len(m) != 0 {
		c.FixedIdentityMapping = m
	}

	c.ConntrackGCInterval = viper.GetDuration(ConntrackGCInterval)

	if m, err := command.GetStringMapStringE(viper.GetViper(), KVStoreOpt); err != nil {
		log.Fatalf("unable to parse %s: %s", KVStoreOpt, err)
	} else {
		c.KVStoreOpt = m
	}

	if m, err := command.GetStringMapStringE(viper.GetViper(), LogOpt); err != nil {
		log.Fatalf("unable to parse %s: %s", LogOpt, err)
	} else {
		c.LogOpt = m
	}

	if m, err := command.GetStringMapStringE(viper.GetViper(), APIRateLimitName); err != nil {
		log.Fatalf("unable to parse %s: %s", APIRateLimitName, err)
	} else {
		c.APIRateLimit = m
	}

	for _, option := range viper.GetStringSlice(EndpointStatus) {
		c.EndpointStatus[option] = struct{}{}
	}

	if c.MonitorQueueSize == 0 {
		c.MonitorQueueSize = getDefaultMonitorQueueSize(runtime.NumCPU())
	}

	// Metrics Setup
	defaultMetrics := metrics.DefaultMetrics()
	for _, metric := range viper.GetStringSlice(Metrics) {
		switch metric[0] {
		case '+':
			defaultMetrics[metric[1:]] = struct{}{}
		case '-':
			delete(defaultMetrics, metric[1:])
		}
	}
	var collectors []prometheus.Collector
	metricsSlice := common.MapStringStructToSlice(defaultMetrics)
	c.MetricsConfig, collectors = metrics.CreateConfiguration(metricsSlice)
	metrics.MustRegister(collectors...)

	if err := c.parseExcludedLocalAddresses(viper.GetStringSlice(ExcludeLocalAddress)); err != nil {
		log.WithError(err).Fatalf("Unable to parse excluded local addresses")
	}

	c.IdentityAllocationMode = viper.GetString(IdentityAllocationMode)
	switch c.IdentityAllocationMode {
	// This is here for tests. Some call Populate without the normal init
	case "":
		c.IdentityAllocationMode = IdentityAllocationModeKVstore

	case IdentityAllocationModeKVstore, IdentityAllocationModeCRD:
		// c.IdentityAllocationMode is set above

	default:
		log.Fatalf("Invalid identity allocation mode %q. It must be one of %s or %s", c.IdentityAllocationMode, IdentityAllocationModeKVstore, IdentityAllocationModeCRD)
	}
	if c.KVStore == "" {
		if c.IdentityAllocationMode != IdentityAllocationModeCRD {
			log.Warningf("Running Cilium with %q=%q requires identity allocation via CRDs. Changing %s to %q", KVStore, c.KVStore, IdentityAllocationMode, IdentityAllocationModeCRD)
			c.IdentityAllocationMode = IdentityAllocationModeCRD
		}
		if c.DisableCiliumEndpointCRD {
			log.Warningf("Running Cilium with %q=%q requires endpoint CRDs. Changing %s to %t", KVStore, c.KVStore, DisableCiliumEndpointCRDName, false)
			c.DisableCiliumEndpointCRD = false
		}
		if c.K8sEventHandover {
			log.Warningf("Running Cilium with %q=%q requires KVStore capability. Changing %s to %t", KVStore, c.KVStore, K8sEventHandover, false)
			c.K8sEventHandover = false
		}
	}

	switch c.IPAM {
	case ipamOption.IPAMKubernetes, ipamOption.IPAMClusterPool, ipamOption.IPAMClusterPoolV2:
		if c.EnableIPv4 {
			c.K8sRequireIPv4PodCIDR = true
		}

		if c.EnableIPv6 {
			c.K8sRequireIPv6PodCIDR = true
		}
	}

	c.KubeProxyReplacementHealthzBindAddr = viper.GetString(KubeProxyReplacementHealthzBindAddr)

	// Hubble options.
	c.EnableHubble = viper.GetBool(EnableHubble)
	c.HubbleSocketPath = viper.GetString(HubbleSocketPath)
	c.HubbleListenAddress = viper.GetString(HubbleListenAddress)
	c.HubbleTLSDisabled = viper.GetBool(HubbleTLSDisabled)
	c.HubbleTLSCertFile = viper.GetString(HubbleTLSCertFile)
	c.HubbleTLSKeyFile = viper.GetString(HubbleTLSKeyFile)
	c.HubbleTLSClientCAFiles = viper.GetStringSlice(HubbleTLSClientCAFiles)
	c.HubbleEventBufferCapacity = viper.GetInt(HubbleEventBufferCapacity)
	c.HubbleEventQueueSize = viper.GetInt(HubbleEventQueueSize)
	if c.HubbleEventQueueSize == 0 {
		c.HubbleEventQueueSize = getDefaultMonitorQueueSize(runtime.NumCPU())
	}
	c.HubbleMetricsServer = viper.GetString(HubbleMetricsServer)
	c.HubbleMetrics = viper.GetStringSlice(HubbleMetrics)
	c.HubbleExportFilePath = viper.GetString(HubbleExportFilePath)
	c.HubbleExportFileMaxSizeMB = viper.GetInt(HubbleExportFileMaxSizeMB)
	c.HubbleExportFileMaxBackups = viper.GetInt(HubbleExportFileMaxBackups)
	c.HubbleExportFileCompress = viper.GetBool(HubbleExportFileCompress)
	c.EnableHubbleRecorderAPI = viper.GetBool(EnableHubbleRecorderAPI)
	c.HubbleRecorderStoragePath = viper.GetString(HubbleRecorderStoragePath)
	c.HubbleRecorderSinkQueueSize = viper.GetInt(HubbleRecorderSinkQueueSize)
	c.DisableIptablesFeederRules = viper.GetStringSlice(DisableIptablesFeederRules)
	c.EnableCiliumEndpointSlice = viper.GetBool(EnableCiliumEndpointSlice)

	// Hidden options
	c.CompilerFlags = viper.GetStringSlice(CompilerFlags)
	c.ConfigFile = viper.GetString(ConfigFile)
	c.HTTP403Message = viper.GetString(HTTP403Message)
	c.DisableEnvoyVersionCheck = viper.GetBool(DisableEnvoyVersionCheck)
	c.K8sNamespace = viper.GetString(K8sNamespaceName)
	c.MaxControllerInterval = viper.GetInt(MaxCtrlIntervalName)
	c.PolicyQueueSize = sanitizeIntParam(PolicyQueueSize, defaults.PolicyQueueSize)
	c.EndpointQueueSize = sanitizeIntParam(EndpointQueueSize, defaults.EndpointQueueSize)
	c.EndpointGCInterval = viper.GetDuration(EndpointGCInterval)
	c.SelectiveRegeneration = viper.GetBool(SelectiveRegeneration)
	c.DisableCNPStatusUpdates = viper.GetBool(DisableCNPStatusUpdates)
	c.EnableICMPRules = viper.GetBool(EnableICMPRules)
	c.BypassIPAvailabilityUponRestore = viper.GetBool(BypassIPAvailabilityUponRestore)
	c.EnableK8sTerminatingEndpoint = viper.GetBool(EnableK8sTerminatingEndpoint)

	// VTEP integration enable option
	c.EnableVTEP = viper.GetBool(EnableVTEP)

	// Enable BGP control plane features
	c.EnableBGPControlPlane = viper.GetBool(EnableBGPControlPlane)
}

func (c *DaemonConfig) populateDevices() {
	c.Devices = viper.GetStringSlice(Devices)

	// Make sure that devices are unique
	if len(c.Devices) <= 1 {
		return
	}
	devSet := map[string]struct{}{}
	for _, dev := range c.Devices {
		devSet[dev] = struct{}{}
	}
	c.Devices = make([]string, 0, len(devSet))
	for dev := range devSet {
		c.Devices = append(c.Devices, dev)
	}
}

func (c *DaemonConfig) populateLoadBalancerSettings() {
	c.NodePortAcceleration = viper.GetString(LoadBalancerAcceleration)
	c.NodePortMode = viper.GetString(LoadBalancerMode)
	c.NodePortAlg = viper.GetString(LoadBalancerAlg)
	// If old settings were explicitly set by the user, then have them
	// override the new ones in order to not break existing setups.
	if viper.IsSet(NodePortAcceleration) {
		prior := c.NodePortAcceleration
		c.NodePortAcceleration = viper.GetString(NodePortAcceleration)
		if viper.IsSet(LoadBalancerAcceleration) && prior != c.NodePortAcceleration {
			log.Fatalf("Both --%s and --%s were set. Only use --%s instead.",
				LoadBalancerAcceleration, NodePortAcceleration, LoadBalancerAcceleration)
		}
	}
	if viper.IsSet(NodePortMode) {
		prior := c.NodePortMode
		c.NodePortMode = viper.GetString(NodePortMode)
		if viper.IsSet(LoadBalancerMode) && prior != c.NodePortMode {
			log.Fatalf("Both --%s and --%s were set. Only use --%s instead.",
				LoadBalancerMode, NodePortMode, LoadBalancerMode)
		}
	}
	if viper.IsSet(NodePortAlg) {
		prior := c.NodePortAlg
		c.NodePortAlg = viper.GetString(NodePortAlg)
		if viper.IsSet(LoadBalancerAlg) && prior != c.NodePortAlg {
			log.Fatalf("Both --%s and --%s were set. Only use --%s instead.",
				LoadBalancerAlg, NodePortAlg, LoadBalancerAlg)
		}
	}
}

func (c *DaemonConfig) populateNodePortRange() error {
	nodePortRange := viper.GetStringSlice(NodePortRange)
	// When passed via configmap, we might not get a slice but single
	// string instead, so split it if needed.
	if len(nodePortRange) == 1 {
		nodePortRange = strings.Split(nodePortRange[0], ",")
	}
	switch len(nodePortRange) {
	case 2:
		var err error

		c.NodePortMin, err = strconv.Atoi(nodePortRange[0])
		if err != nil {
			return fmt.Errorf("Unable to parse min port value for NodePort range: %s", err.Error())
		}
		c.NodePortMax, err = strconv.Atoi(nodePortRange[1])
		if err != nil {
			return fmt.Errorf("Unable to parse max port value for NodePort range: %s", err.Error())
		}
		if c.NodePortMax <= c.NodePortMin {
			return errors.New("NodePort range min port must be smaller than max port")
		}
	case 0:
		if viper.IsSet(NodePortRange) {
			log.Warning("NodePort range was set but is empty.")
		}
	default:
		return fmt.Errorf("Unable to parse min/max port value for NodePort range: %s", NodePortRange)
	}

	return nil
}

func (c *DaemonConfig) populateHostServicesProtos() error {
	hostServicesProtos := viper.GetStringSlice(HostReachableServicesProtos)
	// When passed via configmap, we might not get a slice but single
	// string instead, so split it if needed.
	if len(hostServicesProtos) == 1 {
		hostServicesProtos = strings.Split(hostServicesProtos[0], ",")
	}
	if len(hostServicesProtos) > 2 {
		return fmt.Errorf("More than two protocols for host reachable services not supported: %s",
			hostServicesProtos)
	}
	for i := 0; i < len(hostServicesProtos); i++ {
		switch strings.ToLower(hostServicesProtos[i]) {
		case HostServicesTCP:
			c.EnableHostServicesTCP = true
		case HostServicesUDP:
			c.EnableHostServicesUDP = true
		default:
			return fmt.Errorf("Protocol other than %s,%s not supported for host reachable services: %s",
				HostServicesTCP, HostServicesUDP, hostServicesProtos[i])
		}
	}

	return nil
}

func (c *DaemonConfig) checkMapSizeLimits() error {
	if c.CTMapEntriesGlobalTCP < LimitTableMin || c.CTMapEntriesGlobalAny < LimitTableMin {
		return fmt.Errorf("specified CT tables values %d/%d must exceed minimum %d",
			c.CTMapEntriesGlobalTCP, c.CTMapEntriesGlobalAny, LimitTableMin)
	}
	if c.CTMapEntriesGlobalTCP > LimitTableMax || c.CTMapEntriesGlobalAny > LimitTableMax {
		return fmt.Errorf("specified CT tables values %d/%d must not exceed maximum %d",
			c.CTMapEntriesGlobalTCP, c.CTMapEntriesGlobalAny, LimitTableMax)
	}

	if c.NATMapEntriesGlobal < LimitTableMin {
		return fmt.Errorf("specified NAT table size %d must exceed minimum %d",
			c.NATMapEntriesGlobal, LimitTableMin)
	}
	if c.NATMapEntriesGlobal > LimitTableMax {
		return fmt.Errorf("specified NAT tables size %d must not exceed maximum %d",
			c.NATMapEntriesGlobal, LimitTableMax)
	}
	if c.NATMapEntriesGlobal > c.CTMapEntriesGlobalTCP+c.CTMapEntriesGlobalAny {
		if c.NATMapEntriesGlobal == NATMapEntriesGlobalDefault {
			// Auto-size for the case where CT table size was adapted but NAT still on default
			c.NATMapEntriesGlobal = int((c.CTMapEntriesGlobalTCP + c.CTMapEntriesGlobalAny) * 2 / 3)
		} else {
			return fmt.Errorf("specified NAT tables size %d must not exceed maximum CT table size %d",
				c.NATMapEntriesGlobal, c.CTMapEntriesGlobalTCP+c.CTMapEntriesGlobalAny)
		}
	}

	if c.SockRevNatEntries < LimitTableMin {
		return fmt.Errorf("specified Socket Reverse NAT table size %d must exceed minimum %d",
			c.SockRevNatEntries, LimitTableMin)
	}
	if c.SockRevNatEntries > LimitTableMax {
		return fmt.Errorf("specified Socket Reverse NAT tables size %d must not exceed maximum %d",
			c.SockRevNatEntries, LimitTableMax)
	}

	if c.PolicyMapEntries < PolicyMapMin {
		return fmt.Errorf("specified PolicyMap max entries %d must exceed minimum %d",
			c.PolicyMapEntries, PolicyMapMin)
	}
	if c.PolicyMapEntries > PolicyMapMax {
		return fmt.Errorf("specified PolicyMap max entries %d must not exceed maximum %d",
			c.PolicyMapEntries, PolicyMapMax)
	}

	if c.FragmentsMapEntries < FragmentsMapMin {
		return fmt.Errorf("specified max entries %d for fragment-tracking map must exceed minimum %d",
			c.FragmentsMapEntries, FragmentsMapMin)
	}
	if c.FragmentsMapEntries > FragmentsMapMax {
		return fmt.Errorf("specified max entries %d for fragment-tracking map must not exceed maximum %d",
			c.FragmentsMapEntries, FragmentsMapMax)
	}

	if c.LBMapEntries <= 0 {
		return fmt.Errorf("specified LBMap max entries %d must be a value greater than 0", c.LBMapEntries)
	}

	if c.LBServiceMapEntries < 0 ||
		c.LBBackendMapEntries < 0 ||
		c.LBRevNatEntries < 0 ||
		c.LBAffinityMapEntries < 0 ||
		c.LBSourceRangeMapEntries < 0 ||
		c.LBMaglevMapEntries < 0 {
		return fmt.Errorf("specified LB Service Map max entries must not be a negative value"+
			"(Service Map: %d, Service Backend: %d, Reverse NAT: %d, Session Affinity: %d, Source Range: %d, Maglev: %d)",
			c.LBServiceMapEntries,
			c.LBBackendMapEntries,
			c.LBRevNatEntries,
			c.LBAffinityMapEntries,
			c.LBSourceRangeMapEntries,
			c.LBMaglevMapEntries)
	}
	return nil
}

func (c *DaemonConfig) checkIPv4NativeRoutingCIDR() error {
	if c.GetIPv4NativeRoutingCIDR() == nil && c.EnableIPv4Masquerade && c.Tunnel == TunnelDisabled &&
		c.IPAMMode() != ipamOption.IPAMENI && c.EnableIPv4 && c.IPAMMode() != ipamOption.IPAMAlibabaCloud {
		return fmt.Errorf(
			"native routing cidr must be configured with option --%s "+
				"in combination with --%s --%s=%s --%s=%s --%s=true",
			IPv4NativeRoutingCIDR, EnableIPv4Masquerade, TunnelName, c.Tunnel,
			IPAM, c.IPAMMode(), EnableIPv4Name)
	}

	return nil
}

func (c *DaemonConfig) checkIPv6NativeRoutingCIDR() error {
	if c.GetIPv6NativeRoutingCIDR() == nil && c.EnableIPv6Masquerade && c.Tunnel == TunnelDisabled &&
		c.EnableIPv6 {
		return fmt.Errorf(
			"native routing cidr must be configured with option --%s "+
				"in combination with --%s --%s=%s --%s=true",
			IPv6NativeRoutingCIDR, EnableIPv6Masquerade, TunnelName, c.Tunnel,
			EnableIPv6Name)
	}

	return nil
}

func (c *DaemonConfig) calculateBPFMapSizes() error {
	// BPF map size options
	// Any map size explicitly set via option will override the dynamic
	// sizing.
	c.CTMapEntriesGlobalTCP = viper.GetInt(CTMapEntriesGlobalTCPName)
	c.CTMapEntriesGlobalAny = viper.GetInt(CTMapEntriesGlobalAnyName)
	c.NATMapEntriesGlobal = viper.GetInt(NATMapEntriesGlobalName)
	c.NeighMapEntriesGlobal = viper.GetInt(NeighMapEntriesGlobalName)
	c.PolicyMapEntries = viper.GetInt(PolicyMapEntriesName)
	c.SockRevNatEntries = viper.GetInt(SockRevNatEntriesName)
	c.LBMapEntries = viper.GetInt(LBMapEntriesName)
	c.LBServiceMapEntries = viper.GetInt(LBServiceMapMaxEntries)
	c.LBBackendMapEntries = viper.GetInt(LBBackendMapMaxEntries)
	c.LBRevNatEntries = viper.GetInt(LBRevNatMapMaxEntries)
	c.LBAffinityMapEntries = viper.GetInt(LBAffinityMapMaxEntries)
	c.LBSourceRangeMapEntries = viper.GetInt(LBSourceRangeMapMaxEntries)
	c.LBMaglevMapEntries = viper.GetInt(LBMaglevMapMaxEntries)

	// Don't attempt dynamic sizing if any of the sizeof members was not
	// populated by the daemon (or any other caller).
	if c.SizeofCTElement == 0 ||
		c.SizeofNATElement == 0 ||
		c.SizeofNeighElement == 0 ||
		c.SizeofSockRevElement == 0 {
		return nil
	}

	// Allow the range (0.0, 1.0] because the dynamic size will anyway be
	// clamped to the table limits. Thus, a ratio of e.g. 0.98 will not lead
	// to 98% of the total memory being allocated for BPF maps.
	dynamicSizeRatio := viper.GetFloat64(MapEntriesGlobalDynamicSizeRatioName)
	if 0.0 < dynamicSizeRatio && dynamicSizeRatio <= 1.0 {
		vms, err := mem.VirtualMemory()
		if err != nil || vms == nil {
			log.WithError(err).Fatal("Failed to get system memory")
		}
		c.calculateDynamicBPFMapSizes(vms.Total, dynamicSizeRatio)
		c.BPFMapsDynamicSizeRatio = dynamicSizeRatio
	} else if dynamicSizeRatio < 0.0 {
		return fmt.Errorf("specified dynamic map size ratio %f must be ≥ 0.0", dynamicSizeRatio)
	} else if dynamicSizeRatio > 1.0 {
		return fmt.Errorf("specified dynamic map size ratio %f must be ≤ 1.0", dynamicSizeRatio)
	}
	return nil
}

// SetMapElementSizes sets the BPF map element sizes (key + value) used for
// dynamic BPF map size calculations in calculateDynamicBPFMapSizes.
func (c *DaemonConfig) SetMapElementSizes(
	sizeofCTElement,
	sizeofNATElement,
	sizeofNeighElement,
	sizeofSockRevElement int) {

	c.SizeofCTElement = sizeofCTElement
	c.SizeofNATElement = sizeofNATElement
	c.SizeofNeighElement = sizeofNeighElement
	c.SizeofSockRevElement = sizeofSockRevElement
}

func (c *DaemonConfig) calculateDynamicBPFMapSizes(totalMemory uint64, dynamicSizeRatio float64) {
	// Heuristic:
	// Distribute relative to map default entries among the different maps.
	// Cap each map size by the maximum. Map size provided by the user will
	// override the calculated value and also the max. There will be a check
	// for maximum size later on in DaemonConfig.Validate()
	//
	// Calculation examples:
	//
	// Memory   CT TCP  CT Any      NAT
	//
	//  512MB    33140   16570    33140
	//    1GB    66280   33140    66280
	//    4GB   265121  132560   265121
	//   16GB  1060485  530242  1060485
	memoryAvailableForMaps := int(float64(totalMemory) * dynamicSizeRatio)
	log.Infof("Memory available for map entries (%.3f%% of %dB): %dB", dynamicSizeRatio, totalMemory, memoryAvailableForMaps)
	totalMapMemoryDefault := CTMapEntriesGlobalTCPDefault*c.SizeofCTElement +
		CTMapEntriesGlobalAnyDefault*c.SizeofCTElement +
		NATMapEntriesGlobalDefault*c.SizeofNATElement +
		// Neigh table has the same number of entries as NAT Map has.
		NATMapEntriesGlobalDefault*c.SizeofNeighElement +
		SockRevNATMapEntriesDefault*c.SizeofSockRevElement
	log.Debugf("Total memory for default map entries: %d", totalMapMemoryDefault)

	getEntries := func(entriesDefault, min, max int) int {
		entries := (entriesDefault * memoryAvailableForMaps) / totalMapMemoryDefault
		if entries < min {
			entries = min
		} else if entries > max {
			log.Debugf("clamped from %d to %d", entries, max)
			entries = max
		}
		return entries
	}

	// If value for a particular map was explicitly set by an
	// option, disable dynamic sizing for this map and use the
	// provided size.
	if !viper.IsSet(CTMapEntriesGlobalTCPName) {
		c.CTMapEntriesGlobalTCP =
			getEntries(CTMapEntriesGlobalTCPDefault, LimitTableAutoGlobalTCPMin, LimitTableMax)
		log.Infof("option %s set by dynamic sizing to %v",
			CTMapEntriesGlobalTCPName, c.CTMapEntriesGlobalTCP)
	} else {
		log.Debugf("option %s set by user to %v", CTMapEntriesGlobalTCPName, c.CTMapEntriesGlobalTCP)
	}
	if !viper.IsSet(CTMapEntriesGlobalAnyName) {
		c.CTMapEntriesGlobalAny =
			getEntries(CTMapEntriesGlobalAnyDefault, LimitTableAutoGlobalAnyMin, LimitTableMax)
		log.Infof("option %s set by dynamic sizing to %v",
			CTMapEntriesGlobalAnyName, c.CTMapEntriesGlobalAny)
	} else {
		log.Debugf("option %s set by user to %v", CTMapEntriesGlobalAnyName, c.CTMapEntriesGlobalAny)
	}
	if !viper.IsSet(NATMapEntriesGlobalName) {
		c.NATMapEntriesGlobal =
			getEntries(NATMapEntriesGlobalDefault, LimitTableAutoNatGlobalMin, LimitTableMax)
		log.Infof("option %s set by dynamic sizing to %v",
			NATMapEntriesGlobalName, c.NATMapEntriesGlobal)
		if c.NATMapEntriesGlobal > c.CTMapEntriesGlobalTCP+c.CTMapEntriesGlobalAny {
			// CT table size was specified manually, make sure that the NAT table size
			// does not exceed maximum CT table size. See
			// (*DaemonConfig).checkMapSizeLimits.
			c.NATMapEntriesGlobal = (c.CTMapEntriesGlobalTCP + c.CTMapEntriesGlobalAny) * 2 / 3
			log.Warningf("option %s would exceed maximum determined by CT table sizes, capping to %v",
				NATMapEntriesGlobalName, c.NATMapEntriesGlobal)
		}
	} else {
		log.Debugf("option %s set by user to %v", NATMapEntriesGlobalName, c.NATMapEntriesGlobal)
	}
	if !viper.IsSet(NeighMapEntriesGlobalName) {
		// By default we auto-size it to the same value as the NAT map since we
		// need to keep at least as many neigh entries.
		c.NeighMapEntriesGlobal = c.NATMapEntriesGlobal
		log.Infof("option %s set by dynamic sizing to %v",
			NeighMapEntriesGlobalName, c.NeighMapEntriesGlobal)
	} else {
		log.Debugf("option %s set by user to %v", NeighMapEntriesGlobalName, c.NeighMapEntriesGlobal)
	}
	if !viper.IsSet(SockRevNatEntriesName) {
		c.SockRevNatEntries =
			getEntries(SockRevNATMapEntriesDefault, LimitTableAutoSockRevNatMin, LimitTableMax)
		log.Infof("option %s set by dynamic sizing to %v",
			SockRevNatEntriesName, c.SockRevNatEntries)
	} else {
		log.Debugf("option %s set by user to %v", NATMapEntriesGlobalName, c.NATMapEntriesGlobal)
	}
}

// Validate VTEP integration configuration
func (c *DaemonConfig) validateVTEP() error {
	vtepEndpoints := viper.GetStringSlice(VtepEndpoint)
	vtepCIDRs := viper.GetStringSlice(VtepCIDR)
	vtepCidrMask := viper.GetString(VtepMask)
	vtepMACs := viper.GetStringSlice(VtepMAC)

	if (len(vtepEndpoints) < 1) ||
		len(vtepEndpoints) != len(vtepCIDRs) ||
		len(vtepEndpoints) != len(vtepMACs) {
		return fmt.Errorf("VTEP configuration must have the same number of Endpoint, VTEP and MAC configurations (Found %d endpoints, %d MACs, %d CIDR ranges)", len(vtepEndpoints), len(vtepMACs), len(vtepCIDRs))
	}
	if len(vtepEndpoints) > defaults.MaxVTEPDevices {
		return fmt.Errorf("VTEP must not exceed %d VTEP devices (Found %d VTEPs)", defaults.MaxVTEPDevices, len(vtepEndpoints))
	}
	for _, ep := range vtepEndpoints {
		endpoint := net.ParseIP(ep)
		if endpoint == nil {
			return fmt.Errorf("Invalid VTEP IP: %v", ep)
		}
		ip4 := endpoint.To4()
		if ip4 == nil {
			return fmt.Errorf("Invalid VTEP IPv4 address %v", ip4)
		}
		c.VtepEndpoints = append(c.VtepEndpoints, endpoint)

	}
	for _, v := range vtepCIDRs {
		externalCIDR, err := cidr.ParseCIDR(v)
		if err != nil {
			return fmt.Errorf("Invalid VTEP CIDR: %v", v)
		}
		c.VtepCIDRs = append(c.VtepCIDRs, externalCIDR)

	}
	mask := net.ParseIP(vtepCidrMask)
	if mask == nil {
		return fmt.Errorf("Invalid VTEP CIDR Mask: %v", vtepCidrMask)
	}
	c.VtepCidrMask = mask
	for _, m := range vtepMACs {
		externalMAC, err := mac.ParseMAC(m)
		if err != nil {
			return fmt.Errorf("Invalid VTEP MAC: %v", m)
		}
		c.VtepMACs = append(c.VtepMACs, externalMAC)

	}
	return nil
}

// KubeProxyReplacementFullyEnabled returns true if Cilium is _effectively_
// running in full KPR mode.
//
// The extra logic to check that all the individual features are enabled is
// required to deal with the case when KubeProxyReplacement mode is set to
// "probe" (as Cilium may or may not be running full KPR mode).
func (c *DaemonConfig) KubeProxyReplacementFullyEnabled() bool {
	return c.EnableHostPort &&
		c.EnableNodePort &&
		c.EnableExternalIPs &&
		c.EnableHostReachableServices &&
		c.EnableHostServicesTCP &&
		c.EnableHostServicesUDP &&
		c.EnableSessionAffinity
}

// StoreInFile stores the configuration in a the given directory under the file
// name 'daemon-config.json'. If this file already exists, it is renamed to
// 'daemon-config-1.json', if 'daemon-config-1.json' also exists,
// 'daemon-config-1.json' is renamed to 'daemon-config-2.json'
func (c *DaemonConfig) StoreInFile(dir string) error {
	backupFileNames := []string{
		"agent-runtime-config.json",
		"agent-runtime-config-1.json",
		"agent-runtime-config-2.json",
	}
	backupFiles(dir, backupFileNames)
	f, err := os.Create(backupFileNames[0])
	if err != nil {
		return err
	}
	defer f.Close()
	e := json.NewEncoder(f)
	e.SetIndent("", " ")
	return e.Encode(c)
}

func (c *DaemonConfig) BGPControlPlaneEnabled() bool {
	return c.EnableBGPControlPlane
}

// StoreViperInFile stores viper's configuration in a the given directory under
// the file name 'viper-config.yaml'. If this file already exists, it is renamed
// to 'viper-config-1.yaml', if 'viper-config-1.yaml' also exists,
// 'viper-config-1.yaml' is renamed to 'viper-config-2.yaml'
func StoreViperInFile(dir string) error {
	backupFileNames := []string{
		"viper-agent-config.yaml",
		"viper-agent-config-1.yaml",
		"viper-agent-config-2.yaml",
	}
	backupFiles(dir, backupFileNames)
	return viper.WriteConfigAs(backupFileNames[0])
}

func backupFiles(dir string, backupFilenames []string) {
	for i := len(backupFilenames) - 1; i > 0; i-- {
		newFileName := filepath.Join(dir, backupFilenames[i-1])
		oldestFilename := filepath.Join(dir, backupFilenames[i])
		if _, err := os.Stat(newFileName); os.IsNotExist(err) {
			continue
		}
		err := os.Rename(newFileName, oldestFilename)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"old-name": oldestFilename,
				"new-name": newFileName,
			}).Error("Unable to rename configuration files")
		}
	}
}

func sanitizeIntParam(paramName string, paramDefault int) int {
	intParam := viper.GetInt(paramName)
	if intParam <= 0 {
		if viper.IsSet(paramName) {
			log.WithFields(
				logrus.Fields{
					"parameter":    paramName,
					"defaultValue": paramDefault,
				}).Warning("user-provided parameter had value <= 0 , which is invalid ; setting to default")
		}
		return paramDefault
	}
	return intParam
}

// validateConfigmap checks whether the flag exists and validate the value of flag
func validateConfigmap(cmd *cobra.Command, m map[string]interface{}) (error, string) {
	// validate the config-map
	for key, value := range m {
		if val := fmt.Sprintf("%v", value); val != "" {
			flags := cmd.Flags()
			// check whether the flag exists
			if flag := flags.Lookup(key); flag != nil {
				// validate the value of flag
				if err := flag.Value.Set(val); err != nil {
					return err, key
				}
			}
		}
	}

	return nil, ""
}

// InitConfig reads in config file and ENV variables if set.
func InitConfig(cmd *cobra.Command, programName, configName string) func() {
	return func() {
		if viper.GetBool("version") {
			fmt.Printf("%s %s\n", programName, version.Version)
			os.Exit(0)
		}

		if viper.GetString(CMDRef) != "" {
			return
		}

		Config.ConfigFile = viper.GetString(ConfigFile) // enable ability to specify config file via flag
		Config.ConfigDir = viper.GetString(ConfigDir)
		viper.SetEnvPrefix("cilium")

		if Config.ConfigDir != "" {
			if _, err := os.Stat(Config.ConfigDir); os.IsNotExist(err) {
				log.Fatalf("Non-existent configuration directory %s", Config.ConfigDir)
			}

			if m, err := ReadDirConfig(Config.ConfigDir); err != nil {
				log.WithError(err).Fatalf("Unable to read configuration directory %s", Config.ConfigDir)
			} else {
				// replace deprecated fields with new fields
				ReplaceDeprecatedFields(m)

				// validate the config-map
				if err, flag := validateConfigmap(cmd, m); err != nil {
					log.WithError(err).Fatal("Incorrect config-map flag " + flag)
				}

				if err := MergeConfig(m); err != nil {
					log.WithError(err).Fatal("Unable to merge configuration")
				}
			}
		}

		if Config.ConfigFile != "" {
			viper.SetConfigFile(Config.ConfigFile)
		} else {
			viper.SetConfigName(configName) // name of config file (without extension)
			viper.AddConfigPath("$HOME")    // adding home directory as first search path
		}

		// If a config file is found, read it in.
		if err := viper.ReadInConfig(); err == nil {
			log.WithField(logfields.Path, viper.ConfigFileUsed()).
				Info("Using config from file")
		} else if Config.ConfigFile != "" {
			log.WithField(logfields.Path, Config.ConfigFile).
				Fatal("Error reading config file")
		} else {
			log.WithError(err).Debug("Skipped reading configuration file")
		}
	}
}

func getDefaultMonitorQueueSize(numCPU int) int {
	monitorQueueSize := numCPU * defaults.MonitorQueueSizePerCPU
	if monitorQueueSize > defaults.MonitorQueueSizePerCPUMaximum {
		monitorQueueSize = defaults.MonitorQueueSizePerCPUMaximum
	}
	return monitorQueueSize
}

// EndpointStatusValues returns all available EndpointStatus option values
func EndpointStatusValues() []string {
	return []string{
		EndpointStatusControllers,
		EndpointStatusHealth,
		EndpointStatusLog,
		EndpointStatusPolicy,
		EndpointStatusState,
	}
}

// EndpointStatusValuesMap returns all EndpointStatus option values as a map
func EndpointStatusValuesMap() (values map[string]struct{}) {
	values = map[string]struct{}{}
	for _, v := range EndpointStatusValues() {
		values[v] = struct{}{}
	}
	return
}

// MightAutoDetectDevices returns true if the device auto-detection might take
// place.
func MightAutoDetectDevices() bool {
	return (Config.EnableHostFirewall && len(Config.Devices) == 0) ||
		(Config.KubeProxyReplacement != KubeProxyReplacementDisabled &&
			(len(Config.Devices) == 0 || Config.DirectRoutingDevice == ""))
}

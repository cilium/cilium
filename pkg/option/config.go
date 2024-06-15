// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mackerelio/go-osstat/memory"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	k8sLabels "k8s.io/apimachinery/pkg/labels"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	clustermeshTypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
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

	// ConntrackGCMaxInterval is the name of the ConntrackGCMaxInterval option
	ConntrackGCMaxInterval = "conntrack-gc-max-interval"

	// DebugArg is the argument enables debugging mode
	DebugArg = "debug"

	// DebugVerbose is the argument enables verbose log message for particular subsystems
	DebugVerbose = "debug-verbose"

	// Devices facing cluster/external network for attaching bpf_host
	Devices = "devices"

	// Forces the auto-detection of devices, even if specific devices are explicitly listed
	ForceDeviceDetection = "force-device-detection"

	// DirectRoutingDevice is the name of a device used to connect nodes in
	// direct routing mode (only required by BPF NodePort)
	DirectRoutingDevice = "direct-routing-device"

	// EnablePolicy enables policy enforcement in the agent.
	EnablePolicy = "enable-policy"

	// EnableExternalIPs enables implementation of k8s services with externalIPs in datapath
	EnableExternalIPs = "enable-external-ips"

	// EnableL7Proxy is the name of the option to enable L7 proxy
	EnableL7Proxy = "enable-l7-proxy"

	// EnableTracing enables tracing mode in the agent.
	EnableTracing = "enable-tracing"

	// EnableIPIPTermination is the name of the option to enable IPIP termination
	EnableIPIPTermination = "enable-ipip-termination"

	// Add unreachable routes on pod deletion
	EnableUnreachableRoutes = "enable-unreachable-routes"

	// EncryptInterface enables encryption on specified interface
	EncryptInterface = "encrypt-interface"

	// EncryptNode enables node IP encryption
	EncryptNode = "encrypt-node"

	// GopsPort is the TCP port for the gops server.
	GopsPort = "gops-port"

	// FixedIdentityMapping is the key-value for the fixed identity mapping
	// which allows to use reserved label for fixed identities
	FixedIdentityMapping = "fixed-identity-mapping"

	// FixedZoneMapping is the key-value for the fixed zone mapping which
	// is used to map zone value (string) from EndpointSlice to ID (uint8)
	// in lb{4,6}_backend in BPF map.
	FixedZoneMapping = "fixed-zone-mapping"

	// IPv4Range is the per-node IPv4 endpoint prefix, e.g. 10.16.0.0/16
	IPv4Range = "ipv4-range"

	// IPv6Range is the per-node IPv6 endpoint prefix, must be /96, e.g. fd02:1:1::/96
	IPv6Range = "ipv6-range"

	// IPv4ServiceRange is the Kubernetes IPv4 services CIDR if not inside cluster prefix
	IPv4ServiceRange = "ipv4-service-range"

	// IPv6ServiceRange is the Kubernetes IPv6 services CIDR if not inside cluster prefix
	IPv6ServiceRange = "ipv6-service-range"

	// IPv6ClusterAllocCIDRName is the name of the IPv6ClusterAllocCIDR option
	IPv6ClusterAllocCIDRName = "ipv6-cluster-alloc-cidr"

	// K8sRequireIPv4PodCIDRName is the name of the K8sRequireIPv4PodCIDR option
	K8sRequireIPv4PodCIDRName = "k8s-require-ipv4-pod-cidr"

	// K8sRequireIPv6PodCIDRName is the name of the K8sRequireIPv6PodCIDR option
	K8sRequireIPv6PodCIDRName = "k8s-require-ipv6-pod-cidr"

	// K8sWatcherEndpointSelector specifies the k8s endpoints that Cilium
	// should watch for.
	K8sWatcherEndpointSelector = "k8s-watcher-endpoint-selector"

	// EnableK8s operation of Kubernetes-related services/controllers.
	// Intended for operating cilium with CNI-compatible orchestrators other than Kubernetes. (default is true)
	EnableK8s = "enable-k8s"

	// K8sAPIServer is the kubernetes api address server (for https use --k8s-kubeconfig-path instead)
	K8sAPIServer = "k8s-api-server"

	// K8sKubeConfigPath is the absolute path of the kubernetes kubeconfig file
	K8sKubeConfigPath = "k8s-kubeconfig-path"

	// K8sServiceCacheSize is service cache size for cilium k8s package.
	K8sServiceCacheSize = "k8s-service-cache-size"

	// K8sSyncTimeout is the timeout since last event was received to synchronize all resources with k8s.
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
	// via XDP ("none", "generic", "native", or "best-effort")
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

	// LoadBalancerExternalControlPlane switch skips connectivity to kube-apiserver
	// which is relevant in lb-only mode
	LoadBalancerExternalControlPlane = "bpf-lb-external-control-plane"

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

	// EnableIdentityMark enables setting the mark field with the identity for
	// local traffic. This may be disabled if chaining modes and Cilium use
	// conflicting marks.
	EnableIdentityMark = "enable-identity-mark"

	// EnableHighScaleIPcache enables the special ipcache mode for high scale
	// clusters. The ipcache content will be reduced to the strict minimum and
	// traffic will be encapsulated to carry security identities.
	EnableHighScaleIPcache = "enable-high-scale-ipcache"

	// AddressScopeMax controls the maximum address scope for addresses to be
	// considered local ones with HOST_ID in the ipcache
	AddressScopeMax = "local-max-addr-scope"

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

	// EnableMasqueradeRouteSource masquerades to the source route IP address instead of the interface one
	EnableMasqueradeRouteSource = "enable-masquerade-to-route-source"

	// EnableIPMasqAgent enables BPF ip-masq-agent
	EnableIPMasqAgent = "enable-ip-masq-agent"

	// EnableIPv4EgressGateway enables the IPv4 egress gateway
	EnableIPv4EgressGateway = "enable-ipv4-egress-gateway"

	// EnableEnvoyConfig enables processing of CiliumClusterwideEnvoyConfig and CiliumEnvoyConfig CRDs
	EnableEnvoyConfig = "enable-envoy-config"

	// IPMasqAgentConfigPath is the configuration file path
	IPMasqAgentConfigPath = "ip-masq-agent-config-path"

	// InstallIptRules sets whether Cilium should install any iptables in general
	InstallIptRules = "install-iptables-rules"

	// InstallNoConntrackIptRules instructs Cilium to install Iptables rules
	// to skip netfilter connection tracking on all pod traffic.
	InstallNoConntrackIptRules = "install-no-conntrack-iptables-rules"

	// ContainerIPLocalReservedPorts instructs the Cilium CNI plugin to reserve
	// the provided comma-separated list of ports in the container network namespace
	ContainerIPLocalReservedPorts = "container-ip-local-reserved-ports"

	// IPv6NodeAddr is the IPv6 address of node
	IPv6NodeAddr = "ipv6-node"

	// IPv4NodeAddr is the IPv4 address of node
	IPv4NodeAddr = "ipv4-node"

	// Restore restores state, if possible, from previous daemon
	Restore = "restore"

	// SocketPath sets daemon's socket path to listen for connections
	SocketPath = "socket-path"

	// StateDir is the directory path to store runtime state
	StateDir = "state-dir"

	// TracePayloadlen length of payload to capture when tracing
	TracePayloadlen = "trace-payloadlen"

	// Version prints the version information
	Version = "version"

	// EnableXDPPrefilter enables XDP-based prefiltering
	EnableXDPPrefilter = "enable-xdp-prefilter"

	// EnableTCX enables attaching endpoint programs using tcx if the kernel supports it
	EnableTCX = "enable-tcx"

	ProcFs = "procfs"

	// PrometheusServeAddr IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	PrometheusServeAddr = "prometheus-serve-addr"

	// ExternalEnvoyProxy defines whether the Envoy is deployed externally in form of a DaemonSet or not.
	ExternalEnvoyProxy = "external-envoy-proxy"

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

	// DNSProxyConcurrencyLimit limits parallel processing of DNS messages in
	// DNS proxy at any given point in time.
	DNSProxyConcurrencyLimit = "dnsproxy-concurrency-limit"

	// DNSProxyConcurrencyProcessingGracePeriod is the amount of grace time to
	// wait while processing DNS messages when the DNSProxyConcurrencyLimit has
	// been reached.
	DNSProxyConcurrencyProcessingGracePeriod = "dnsproxy-concurrency-processing-grace-period"

	// DNSProxyLockCount is the array size containing mutexes which protect
	// against parallel handling of DNS response IPs.
	DNSProxyLockCount = "dnsproxy-lock-count"

	// DNSProxyLockTimeout is timeout when acquiring the locks controlled by
	// DNSProxyLockCount.
	DNSProxyLockTimeout = "dnsproxy-lock-timeout"

	// DNSProxySocketLingerTimeout defines how many seconds we wait for the connection
	// between the DNS proxy and the upstream server to be closed.
	DNSProxySocketLingerTimeout = "dnsproxy-socket-linger-timeout"

	// DNSProxyEnableTransparentMode enables transparent mode for the DNS proxy.
	DNSProxyEnableTransparentMode = "dnsproxy-enable-transparent-mode"

	// DNSProxyInsecureSkipTransparentModeCheck is a hidden flag that allows users
	// to disable transparent mode even if IPSec is enabled
	DNSProxyInsecureSkipTransparentModeCheck = "dnsproxy-insecure-skip-transparent-mode-check"

	// MTUName is the name of the MTU option
	MTUName = "mtu"

	// RouteMetric is the name of the route-metric option
	RouteMetric = "route-metric"

	// DatapathMode is the name of the DatapathMode option
	DatapathMode = "datapath-mode"

	// EnableSocketLB is the name for the option to enable the socket LB
	EnableSocketLB = "bpf-lb-sock"

	// EnableSocketLBTracing is the name for the option to enable the socket LB tracing
	EnableSocketLBTracing = "trace-sock"

	// BPFSocketLBHostnsOnly is the name of the BPFSocketLBHostnsOnly option
	BPFSocketLBHostnsOnly = "bpf-lb-sock-hostns-only"

	// RoutingMode is the name of the option to choose between native routing and tunneling mode
	RoutingMode = "routing-mode"

	// ServiceNoBackendResponse is the name of the option to pick how to handle traffic for services
	// without any backends
	ServiceNoBackendResponse = "service-no-backend-response"

	// ServiceNoBackendResponseReject is the name of the option to reject traffic for services
	// without any backends
	ServiceNoBackendResponseReject = "reject"

	// ServiceNoBackendResponseDrop is the name of the option to drop traffic for services
	// without any backends
	ServiceNoBackendResponseDrop = "drop"

	// MaxInternalTimerDelay sets a maximum on all periodic timers in
	// the agent in order to flush out timer-related bugs in the agent.
	MaxInternalTimerDelay = "max-internal-timer-delay"

	// MonitorAggregationName specifies the MonitorAggregationLevel on the
	// comandline.
	MonitorAggregationName = "monitor-aggregation"

	// MonitorAggregationInterval configures interval for monitor-aggregation
	MonitorAggregationInterval = "monitor-aggregation-interval"

	// MonitorAggregationFlags configures TCP flags used by monitor aggregation.
	MonitorAggregationFlags = "monitor-aggregation-flags"

	// ciliumEnvPrefix is the prefix used for environment variables
	ciliumEnvPrefix = "CILIUM_"

	// CNIChainingMode configures which CNI plugin Cilium is chained with.
	CNIChainingMode = "cni-chaining-mode"

	// CNIChainingTarget is the name of a CNI network in to which we should
	// insert our plugin configuration
	CNIChainingTarget = "cni-chaining-target"

	// AuthMapEntriesMin defines the minimum auth map limit.
	AuthMapEntriesMin = 1 << 8

	// AuthMapEntriesMax defines the maximum auth map limit.
	AuthMapEntriesMax = 1 << 24

	// AuthMapEntriesDefault defines the default auth map limit.
	AuthMapEntriesDefault = 1 << 19

	// AuthMapEntriesName configures max entries for BPF auth map.
	AuthMapEntriesName = "bpf-auth-map-max"

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
	CTMapEntriesTimeoutSYNName         = "bpf-ct-timeout-regular-tcp-syn"
	CTMapEntriesTimeoutFINName         = "bpf-ct-timeout-regular-tcp-fin"
	CTMapEntriesTimeoutTCPName         = "bpf-ct-timeout-regular-tcp"
	CTMapEntriesTimeoutAnyName         = "bpf-ct-timeout-regular-any"
	CTMapEntriesTimeoutSVCTCPName      = "bpf-ct-timeout-service-tcp"
	CTMapEntriesTimeoutSVCTCPGraceName = "bpf-ct-timeout-service-tcp-grace"
	CTMapEntriesTimeoutSVCAnyName      = "bpf-ct-timeout-service-any"

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

	// PolicyMapFullReconciliationInterval sets the interval for performing the full
	// reconciliation of the endpoint policy map.
	PolicyMapFullReconciliationIntervalName = "bpf-policy-map-full-reconciliation-interval"

	// SockRevNatEntriesName configures max entries for BPF sock reverse nat
	// entries.
	SockRevNatEntriesName = "bpf-sock-rev-map-max"

	// EgressGatewayPolicyMapEntriesName configures max entries for egress gateway's policy
	// map.
	EgressGatewayPolicyMapEntriesName = "egress-gateway-policy-map-max"

	// LogSystemLoadConfigName is the name of the option to enable system
	// load loggging
	LogSystemLoadConfigName = "log-system-load"

	// DisableCiliumEndpointCRDName is the name of the option to disable
	// use of the CEP CRD
	DisableCiliumEndpointCRDName = "disable-endpoint-crd"

	// MaxCtrlIntervalName and MaxCtrlIntervalNameEnv allow configuration
	// of MaxControllerInterval.
	MaxCtrlIntervalName = "max-controller-interval"

	// K8sNamespaceName is the name of the K8sNamespace option
	K8sNamespaceName = "k8s-namespace"

	// AgentNotReadyNodeTaintKeyName is the name of the option to set
	// AgentNotReadyNodeTaintKey
	AgentNotReadyNodeTaintKeyName = "agent-not-ready-taint-key"

	// JoinClusterName is the name of the JoinCluster Option
	JoinClusterName = "join-cluster"

	// EnableIPv4Name is the name of the option to enable IPv4 support
	EnableIPv4Name = "enable-ipv4"

	// EnableIPv6Name is the name of the option to enable IPv6 support
	EnableIPv6Name = "enable-ipv6"

	// EnableIPv6NDPName is the name of the option to enable IPv6 NDP support
	EnableIPv6NDPName = "enable-ipv6-ndp"

	// EnableSRv6 is the name of the option to enable SRv6 encapsulation support
	EnableSRv6 = "enable-srv6"

	// SRv6EncapModeName is the name of the option to specify the SRv6 encapsulation mode
	SRv6EncapModeName = "srv6-encap-mode"

	// EnableSCTPName is the name of the option to enable SCTP support
	EnableSCTPName = "enable-sctp"

	// EnableNat46X64Gateway enables L3 based NAT46 and NAT64 gateway
	EnableNat46X64Gateway = "enable-nat46x64-gateway"

	// IPv6MCastDevice is the name of the option to select IPv6 multicast device
	IPv6MCastDevice = "ipv6-mcast-device"

	// BPFEventsDefaultRateLimit specifies limit of messages per second that can be written to
	// BPF events map. This limit is defined for all types of events except dbg and pcap.
	// The number of messages is averaged, meaning that if no messages were written
	// to the map over 5 seconds, it's possible to write more events than the value of rate limit
	// in the 6th second.
	//
	// If BPFEventsDefaultRateLimit > 0, non-zero value for BPFEventsDefaultBurstLimit must also be provided
	// lest the configuration is considered invalid.
	// If both rate and burst limit are 0 or not specified, no limit is imposed.
	BPFEventsDefaultRateLimit = "bpf-events-default-rate-limit"

	// BPFEventsDefaultBurstLimit specifies the maximum number of messages that can be written
	// to BPF events map in 1 second. This limit is defined for all types of events except dbg and pcap.
	//
	// If BPFEventsDefaultBurstLimit > 0, non-zero value for BPFEventsDefaultRateLimit must also be provided
	// lest the configuration is considered invalid.
	// If both burst and rate limit are 0 or not specified, no limit is imposed.
	BPFEventsDefaultBurstLimit = "bpf-events-default-burst-limit"

	// FQDNRejectResponseCode is the name for the option for dns-proxy reject response code
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

	// FQDNRegexCompileLRUSize is the size of the FQDN regex compilation LRU.
	// Useful for heavy but repeated FQDN MatchName or MatchPattern use.
	FQDNRegexCompileLRUSize = "fqdn-regex-compile-lru-size"

	// PreAllocateMapsName is the name of the option PreAllocateMaps
	PreAllocateMapsName = "preallocate-bpf-maps"

	// EnableBPFTProxy option supports enabling or disabling BPF TProxy.
	EnableBPFTProxy = "enable-bpf-tproxy"

	// EnableXTSocketFallbackName is the name of the EnableXTSocketFallback option
	EnableXTSocketFallbackName = "enable-xt-socket-fallback"

	// EnableAutoDirectRoutingName is the name for the EnableAutoDirectRouting option
	EnableAutoDirectRoutingName = "auto-direct-node-routes"

	// DirectRoutingSkipUnreachableName is the name for the DirectRoutingSkipUnreachable option
	DirectRoutingSkipUnreachableName = "direct-routing-skip-unreachable"

	// EnableIPSecName is the name of the option to enable IPSec
	EnableIPSecName = "enable-ipsec"

	// Duration of the IPsec key rotation. After that time, we will clean the
	// previous IPsec key from the node.
	IPsecKeyRotationDuration = "ipsec-key-rotation-duration"

	// Enable watcher for IPsec key. If disabled, a restart of the agent will
	// be necessary on key rotations.
	EnableIPsecKeyWatcher = "enable-ipsec-key-watcher"

	// Enable caching for XfrmState for IPSec. Significantly reduces CPU usage
	// in large clusters.
	EnableIPSecXfrmStateCaching = "enable-ipsec-xfrm-state-caching"

	// IPSecKeyFileName is the name of the option for ipsec key file
	IPSecKeyFileName = "ipsec-key-file"

	// EnableIPSecEncrytpedOverlay is the name of the option which enables
	// the EncryptedOverlay feature.
	//
	// This feature will encrypt overlay traffic before it leaves the cluster.
	EnableIPSecEncryptedOverlay = "enable-ipsec-encrypted-overlay"

	// EnableWireguard is the name of the option to enable WireGuard
	EnableWireguard = "enable-wireguard"

	// EnableL2Announcements is the name of the option to enable l2 announcements
	EnableL2Announcements = "enable-l2-announcements"

	// L2AnnouncerLeaseDuration, if a lease has not been renewed for X amount of time, a new leader can be chosen.
	L2AnnouncerLeaseDuration = "l2-announcements-lease-duration"

	// L2AnnouncerRenewDeadline, the leader will renew the lease every X amount of time.
	L2AnnouncerRenewDeadline = "l2-announcements-renew-deadline"

	// L2AnnouncerRetryPeriod, on renew failure, retry after X amount of time.
	L2AnnouncerRetryPeriod = "l2-announcements-retry-period"

	// EnableEncryptionStrictMode is the name of the option to enable strict encryption mode.
	EnableEncryptionStrictMode = "enable-encryption-strict-mode"

	// EncryptionStrictModeCIDR is the CIDR in which the strict ecryption mode should be enforced.
	EncryptionStrictModeCIDR = "encryption-strict-mode-cidr"

	// EncryptionStrictModeAllowRemoteNodeIdentities allows dynamic lookup of remote node identities.
	// This is required when tunneling is used
	// or direct routing is used and the node CIDR and pod CIDR overlap.
	EncryptionStrictModeAllowRemoteNodeIdentities = "encryption-strict-mode-allow-remote-node-identities"

	// EnableWireguardUserspaceFallback is the name of the option that enables the fallback to WireGuard userspace mode
	EnableWireguardUserspaceFallback = "enable-wireguard-userspace-fallback"

	// WireguardPersistentKeepalivee controls Wireguard PersistentKeepalive option. Set 0 to disable.
	WireguardPersistentKeepalive = "wireguard-persistent-keepalive"

	// NodeEncryptionOptOutLabels is the name of the option for the node-to-node encryption opt-out labels
	NodeEncryptionOptOutLabels = "node-encryption-opt-out-labels"

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

	// EnableHealthCheckLoadBalancerIP is the name of the EnableHealthCheckLoadBalancerIP option
	EnableHealthCheckLoadBalancerIP = "enable-health-check-loadbalancer-ip"

	// PolicyQueueSize is the size of the queues utilized by the policy
	// repository.
	PolicyQueueSize = "policy-queue-size"

	// EndpointQueueSize is the size of the EventQueue per-endpoint.
	EndpointQueueSize = "endpoint-queue-size"

	// EndpointGCInterval interval to attempt garbage collection of
	// endpoints that are no longer alive and healthy.
	EndpointGCInterval = "endpoint-gc-interval"

	// LoopbackIPv4 is the address to use for service loopback SNAT
	LoopbackIPv4 = "ipv4-service-loopback-address"

	// LocalRouterIPv4 is the link-local IPv4 address to use for Cilium router device
	LocalRouterIPv4 = "local-router-ipv4"

	// LocalRouterIPv6 is the link-local IPv6 address to use for Cilium router device
	LocalRouterIPv6 = "local-router-ipv6"

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

	// IPAMMultiPoolPreAllocation defines the pre-allocation value for each IPAM pool
	IPAMMultiPoolPreAllocation = "ipam-multi-pool-pre-allocation"

	// IPAMDefaultIPPool defines the default IP Pool when using multi-pool
	IPAMDefaultIPPool = "ipam-default-ip-pool"

	// XDPModeNative for loading progs with XDPModeLinkDriver
	XDPModeNative = "native"

	// XDPModeBestEffort for loading progs with XDPModeLinkDriver
	XDPModeBestEffort = "best-effort"

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

	// ExcludeNodeLabelPatterns allows for excluding unnecessary labels from being propagated from k8s node to cilium
	// node object. This allows for avoiding unnecessary events being broadcast to all nodes in the cluster.
	ExcludeNodeLabelPatterns = "exclude-node-label-patterns"

	// IPv4NativeRoutingCIDR describes a v4 CIDR in which pod IPs are routable
	IPv4NativeRoutingCIDR = "ipv4-native-routing-cidr"

	// IPv6NativeRoutingCIDR describes a v6 CIDR in which pod IPs are routable
	IPv6NativeRoutingCIDR = "ipv6-native-routing-cidr"

	// MasqueradeInterfaces is the selector used to select interfaces subject to
	// egress masquerading
	MasqueradeInterfaces = "egress-masquerade-interfaces"

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

	// EnableLocalNodeRoute controls installation of the route which points
	// the allocation prefix of the local node.
	EnableLocalNodeRoute = "enable-local-node-route"

	// EnableWellKnownIdentities enables the use of well-known identities.
	// This is requires if identiy resolution is required to bring up the
	// control plane, e.g. when using the managed etcd feature
	EnableWellKnownIdentities = "enable-well-known-identities"

	// PolicyAuditModeArg argument enables policy audit mode.
	PolicyAuditModeArg = "policy-audit-mode"

	// PolicyAccountingArg argument enable policy accounting.
	PolicyAccountingArg = "policy-accounting"

	// EnableHubble enables hubble in the agent.
	EnableHubble = "enable-hubble"

	// HubbleSocketPath specifies the UNIX domain socket for Hubble server to listen to.
	HubbleSocketPath = "hubble-socket-path"

	// HubbleListenAddress specifies address for Hubble server to listen to.
	HubbleListenAddress = "hubble-listen-address"

	// HubblePreferIpv6 controls whether IPv6 or IPv4 addresses should be preferred for
	// communication to agents, if both are available.
	HubblePreferIpv6 = "hubble-prefer-ipv6"

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

	// HubbleMetricsTLSEnabled allows the Hubble metrics server to run on the given listen
	// address with TLS.
	HubbleMetricsTLSEnabled = "hubble-metrics-server-enable-tls"

	// HubbleMetricsServerTLSCertFile specifies the path to the public key file for the
	// Hubble metrics server. The file must contain PEM encoded data.
	HubbleMetricsTLSCertFile = "hubble-metrics-server-tls-cert-file"

	// HubbleMetricsServerTLSKeyFile specifies the path to the private key file for the
	// Hubble metrics server. The file must contain PEM encoded data.
	HubbleMetricsTLSKeyFile = "hubble-metrics-server-tls-key-file"

	// HubbleMetricsServerTLSClientCAFiles specifies the path to one or more client CA
	// certificates to use for TLS with mutual authentication (mTLS) on the Hubble metrics server.
	// The files must contain PEM encoded data.
	HubbleMetricsTLSClientCAFiles = "hubble-metrics-server-tls-client-ca-files"

	// HubbleMetrics specifies enabled metrics and their configuration options.
	HubbleMetrics = "hubble-metrics"

	// HubbleFlowlogsConfigFilePath specifies the filepath with configuration of hubble flowlogs.
	// e.g. "/etc/cilium/flowlog.yaml"
	HubbleFlowlogsConfigFilePath = "hubble-flowlogs-config-path"

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

	// HubbleExportAllowlist specifies allow list filter use by exporter.
	HubbleExportAllowlist = "hubble-export-allowlist"

	// HubbleExportDenylist specifies deny list filter use by exporter.
	HubbleExportDenylist = "hubble-export-denylist"

	// HubbleExportFieldmask specifies list of fields to log in exporter.
	HubbleExportFieldmask = "hubble-export-fieldmask"

	// EnableHubbleRecorderAPI specifies if the Hubble Recorder API should be served
	EnableHubbleRecorderAPI = "enable-hubble-recorder-api"

	// EnableHubbleOpenMetrics enables exporting hubble metrics in OpenMetrics format.
	EnableHubbleOpenMetrics = "enable-hubble-open-metrics"

	// HubbleRecorderStoragePath specifies the directory in which pcap files
	// created via the Hubble Recorder API are stored
	HubbleRecorderStoragePath = "hubble-recorder-storage-path"

	// HubbleRecorderSinkQueueSize is the queue size for each recorder sink
	HubbleRecorderSinkQueueSize = "hubble-recorder-sink-queue-size"

	// HubbleSkipUnknownCGroupIDs specifies if events with unknown cgroup ids should be skipped
	HubbleSkipUnknownCGroupIDs = "hubble-skip-unknown-cgroup-ids"

	// HubbleMonitorEvents specifies Cilium monitor events for Hubble to observe.
	// By default, Hubble observes all monitor events.
	HubbleMonitorEvents = "hubble-monitor-events"

	// HubbleRedactEnabled controls if sensitive information will be redacted from L7 flows
	HubbleRedactEnabled = "hubble-redact-enabled"

	// HubbleRedactHttpURLQuery controls if the URL query will be redacted from flows
	HubbleRedactHttpURLQuery = "hubble-redact-http-urlquery"

	// HubbleRedactHttpUserInfo controls if the user info will be redacted from flows
	HubbleRedactHttpUserInfo = "hubble-redact-http-userinfo"

	// HubbleRedactKafkaApiKey controls if the Kafka API key will be redacted from flows
	HubbleRedactKafkaApiKey = "hubble-redact-kafka-apikey"

	// HubbleRedactHttpHeadersAllow controls which http headers will not be redacted from flows
	HubbleRedactHttpHeadersAllow = "hubble-redact-http-headers-allow"

	// HubbleRedactHttpHeadersDeny controls which http headers will be redacted from flows
	HubbleRedactHttpHeadersDeny = "hubble-redact-http-headers-deny"

	// HubbleDropEvents controls whether Hubble should create v1.Events
	// for packet drops related to pods
	HubbleDropEvents = "hubble-drop-events"

	// HubbleDropEventsInterval controls the minimum time between emitting events
	// with the same source and destination IP
	HubbleDropEventsInterval = "hubble-drop-events-interval"

	// HubbleDropEventsReasons controls which drop reasons to emit events for
	HubbleDropEventsReasons = "hubble-drop-events-reasons"

	// K8sClientConnectionTimeout configures the timeout for K8s client connections.
	K8sClientConnectionTimeout = "k8s-client-connection-timeout"

	// K8sClientConnectionKeepAlive configures the keep alive duration for K8s client connections.
	K8sClientConnectionKeepAlive = "k8s-client-connection-keep-alive"

	// K8sHeartbeatTimeout configures the timeout for apiserver heartbeat
	K8sHeartbeatTimeout = "k8s-heartbeat-timeout"

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

	// CRDWaitTimeout is the timeout in which Cilium will exit if CRDs are not
	// available.
	CRDWaitTimeout = "crd-wait-timeout"

	// EgressMultiHomeIPRuleCompat instructs Cilium to use a new scheme to
	// store rules and routes under ENI and Azure IPAM modes, if false.
	// Otherwise, it will use the old scheme.
	EgressMultiHomeIPRuleCompat = "egress-multi-home-ip-rule-compat"

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

	// BGPSecretsNamespace is the Kubernetes namespace to get BGP control plane secrets from.
	BGPSecretsNamespace = "bgp-secrets-namespace"

	// ExternalClusterIPName is the name of the option to enable
	// cluster external access to ClusterIP services.
	ExternalClusterIPName = "bpf-lb-external-clusterip"

	// VLANBPFBypass instructs Cilium to bypass bpf logic for vlan tagged packets
	VLANBPFBypass = "vlan-bpf-bypass"

	// DisableExternalIPMitigation disable ExternalIP mitigation (CVE-2020-8554)
	DisableExternalIPMitigation = "disable-external-ip-mitigation"

	// EnableICMPRules enables ICMP-based rule support for Cilium Network Policies.
	EnableICMPRules = "enable-icmp-rules"

	// Use the CiliumInternalIPs (vs. NodeInternalIPs) for IPsec encapsulation.
	UseCiliumInternalIPForIPsec = "use-cilium-internal-ip-for-ipsec"

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

	// EnableRuntimeDeviceDetection is the name of the option to enable detection
	// of new and removed datapath devices during the agent runtime.
	EnableRuntimeDeviceDetection = "enable-runtime-device-detection"

	// EnablePMTUDiscovery enables path MTU discovery to send ICMP
	// fragmentation-needed replies to the client (when needed).
	EnablePMTUDiscovery = "enable-pmtu-discovery"

	// BPFMapEventBuffers specifies what maps should have event buffers enabled,
	// and the max size and TTL of events in the buffers should be.
	BPFMapEventBuffers = "bpf-map-event-buffers"

	// IPAMCiliumnodeUpdateRate is the maximum rate at which the CiliumNode custom
	// resource is updated.
	IPAMCiliumNodeUpdateRate = "ipam-cilium-node-update-rate"

	// EnableK8sNetworkPolicy enables support for K8s NetworkPolicy.
	EnableK8sNetworkPolicy = "enable-k8s-networkpolicy"

	// PolicyCIDRMatchMode defines the entities that CIDR selectors can reach
	PolicyCIDRMatchMode = "policy-cidr-match-mode"

	// EnableNodeSelectorLabels enables use of the node label based identity
	EnableNodeSelectorLabels = "enable-node-selector-labels"

	// NodeLabels is the list of label prefixes used to determine identity of a node (requires enabling of
	// EnableNodeSelectorLabels)
	NodeLabels = "node-labels"

	// BPFEventsDropEnabled defines the DropNotification setting for any endpoint
	BPFEventsDropEnabled = "bpf-events-drop-enabled"

	// BPFEventsPolicyVerdictEnabled defines the PolicyVerdictNotification setting for any endpoint
	BPFEventsPolicyVerdictEnabled = "bpf-events-policy-verdict-enabled"

	// BPFEventsTraceEnabled defines the TraceNotification setting for any endpoint
	BPFEventsTraceEnabled = "bpf-events-trace-enabled"
)

// Default string arguments
var (
	FQDNRejectOptions = []string{FQDNProxyDenyWithNameError, FQDNProxyDenyWithRefused}

	// MonitorAggregationFlagsDefault ensure that all TCP flags trigger
	// monitor notifications even under medium monitor aggregation.
	MonitorAggregationFlagsDefault = []string{"syn", "fin", "rst"}
)

// Available options for DaemonConfig.RoutingMode
const (
	// RoutingModeNative specifies native routing mode
	RoutingModeNative = "native"

	// RoutingModeTunnel specifies tunneling mode
	RoutingModeTunnel = "tunnel"
)

const (
	// HTTP403Message specifies the response body for 403 responses, defaults to "Access denied"
	HTTP403Message = "http-403-msg"

	// ReadCNIConfiguration reads the CNI configuration file and extracts
	// Cilium relevant information. This can be used to pass per node
	// configuration to Cilium.
	ReadCNIConfiguration = "read-cni-conf"

	// WriteCNIConfigurationWhenReady writes the CNI configuration to the
	// specified location once the agent is ready to serve requests. This
	// allows to keep a Kubernetes node NotReady until Cilium is up and
	// running and able to schedule endpoints.
	WriteCNIConfigurationWhenReady = "write-cni-conf-when-ready"

	// CNIExclusive tells the agent to remove other CNI configuration files
	CNIExclusive = "cni-exclusive"

	// CNIExternalRouting delegates endpoint routing to the chained CNI plugin.
	CNIExternalRouting = "cni-external-routing"

	// CNILogFile is the path to a log file (on the host) for the CNI plugin
	// binary to use for logging.
	CNILogFile = "cni-log-file"

	// EnableCiliumEndpointSlice enables the cilium endpoint slicing feature.
	EnableCiliumEndpointSlice = "enable-cilium-endpoint-slice"

	// EnableExternalWorkloads enables the support for external workloads.
	EnableExternalWorkloads = "enable-external-workloads"
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

	// NodePortModeHybrid is a dual mode of the above, that is, DSR for TCP and SNAT for UDP
	NodePortModeHybrid = "hybrid"

	// NodePortAlgRandom is for randomly selecting a backend
	NodePortAlgRandom = "random"

	// NodePortAlgMaglev is for using maglev consistent hashing for backend selection
	NodePortAlgMaglev = "maglev"

	// DSR dispatch mode to encode service into IP option or extension header
	DSRDispatchOption = "opt"

	// DSR dispatch mode to encapsulate to IPIP
	DSRDispatchIPIP = "ipip"

	// DSR dispatch mode to encapsulate to Geneve
	DSRDispatchGeneve = "geneve"

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

	// NodePortAccelerationBestEffort means we accelerate NodePort via native XDP in the driver (preferred), but will skip devices without driver support
	NodePortAccelerationBestEffort = XDPModeBestEffort

	// KubeProxyReplacementTrue specifies to enable all kube-proxy replacement
	// features (might panic).
	KubeProxyReplacementTrue = "true"

	// KubeProxyReplacementFalse specifies to enable only selected kube-proxy
	// replacement features (might panic).
	KubeProxyReplacementFalse = "false"

	// KubeProxyReplacement healthz server bind address
	KubeProxyReplacementHealthzBindAddr = "kube-proxy-replacement-healthz-bind-address"

	// PprofAddressAgent is the default value for pprof in the agent
	PprofAddressAgent = "localhost"

	// PprofPortAgent is the default value for pprof in the agent
	PprofPortAgent = 6060
)

// getEnvName returns the environment variable to be used for the given option name.
func getEnvName(option string) string {
	under := strings.Replace(option, "-", "_", -1)
	upper := strings.ToUpper(under)
	return ciliumEnvPrefix + upper
}

// BindEnv binds the option name with a deterministic generated environment
// variable which is based on the given optName. If the same optName is bound
// more than once, this function panics.
func BindEnv(vp *viper.Viper, optName string) {
	vp.BindEnv(optName, getEnvName(optName))
}

// BindEnvWithLegacyEnvFallback binds the given option name with either the same
// environment variable as BindEnv, if it's set, or with the given legacyEnvName.
//
// The function is used to work around the viper.BindEnv limitation that only
// one environment variable can be bound for an option, and we need multiple
// environment variables due to backward compatibility reasons.
func BindEnvWithLegacyEnvFallback(vp *viper.Viper, optName, legacyEnvName string) {
	envName := getEnvName(optName)
	if os.Getenv(envName) == "" {
		envName = legacyEnvName
	}
	vp.BindEnv(optName, envName)
}

// LogRegisteredOptions logs all options that where bound to viper.
func LogRegisteredOptions(vp *viper.Viper, entry *logrus.Entry) {
	keys := vp.AllKeys()
	sort.Strings(keys)
	for _, k := range keys {
		ss := vp.GetStringSlice(k)
		if len(ss) == 0 {
			sm := vp.GetStringMap(k)
			for k, v := range sm {
				ss = append(ss, fmt.Sprintf("%s=%s", k, v))
			}
		}

		if len(ss) > 0 {
			entry.Infof("  --%s='%s'", k, strings.Join(ss, ","))
		} else {
			entry.Infof("  --%s='%s'", k, vp.GetString(k))
		}
	}
}

// DaemonConfig is the configuration used by Daemon.
type DaemonConfig struct {
	// Private sum of the config written to file. Used to check that the config is not changed
	// after.
	shaSum [32]byte

	CreationTime        time.Time
	BpfDir              string   // BPF template files directory
	LibDir              string   // Cilium library files directory
	RunDir              string   // Cilium runtime directory
	ExternalEnvoyProxy  bool     // Whether Envoy is deployed as external DaemonSet or not
	DirectRoutingDevice string   // Direct routing device (used by BPF NodePort and BPF Host Routing)
	LBDevInheritIPAddr  string   // Device which IP addr used by bpf_host devices
	EnableXDPPrefilter  bool     // Enable XDP-based prefiltering
	XDPMode             string   // XDP mode, values: { xdpdrv | xdpgeneric | none }
	EnableTCX           bool     // Enable attaching endpoint programs using tcx if the kernel supports it
	HostV4Addr          net.IP   // Host v4 address of the snooping device
	HostV6Addr          net.IP   // Host v6 address of the snooping device
	EncryptInterface    []string // Set of network facing interface to encrypt over
	EncryptNode         bool     // Set to true for encrypting node IP traffic

	// If set to true the daemon will detect new and deleted datapath devices
	// at runtime and reconfigure the datapath to load programs onto the new
	// devices.
	EnableRuntimeDeviceDetection bool

	DatapathMode string // Datapath mode
	RoutingMode  string // Routing mode

	DryMode bool // Do not create BPF maps, devices, ..

	// RestoreState enables restoring the state from previous running daemons.
	RestoreState bool

	KeepConfig bool // Keep configuration of existing endpoints when starting up.

	// AllowLocalhost defines when to allows the local stack to local endpoints
	// values: { auto | always | policy }
	AllowLocalhost string

	// StateDir is the directory where runtime state of endpoints is stored
	StateDir string

	// Options changeable at runtime
	Opts *IntOptions

	// Mutex for serializing configuration updates to the daemon.
	ConfigPatchMutex *lock.RWMutex

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

	// IPv6NAT46x64CIDR is the private base CIDR for the NAT46x64 gateway
	IPv6NAT46x64CIDR string

	// IPv6NAT46x64CIDRBase is derived from IPv6NAT46x64CIDR and contains
	// the IPv6 prefix with the masked bits zeroed out
	IPv6NAT46x64CIDRBase netip.Addr

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
	ClusterID uint32

	// CTMapEntriesGlobalTCP is the maximum number of conntrack entries
	// allowed in each TCP CT table for IPv4/IPv6.
	CTMapEntriesGlobalTCP int

	// CTMapEntriesGlobalAny is the maximum number of conntrack entries
	// allowed in each non-TCP CT table for IPv4/IPv6.
	CTMapEntriesGlobalAny int

	// CTMapEntriesTimeout* values configured by the user.
	CTMapEntriesTimeoutTCP         time.Duration
	CTMapEntriesTimeoutAny         time.Duration
	CTMapEntriesTimeoutSVCTCP      time.Duration
	CTMapEntriesTimeoutSVCTCPGrace time.Duration
	CTMapEntriesTimeoutSVCAny      time.Duration
	CTMapEntriesTimeoutSYN         time.Duration
	CTMapEntriesTimeoutFIN         time.Duration

	// MaxInternalTimerDelay sets a maximum on all periodic timers in
	// the agent in order to flush out timer-related bugs in the agent.
	MaxInternalTimerDelay time.Duration

	// MonitorAggregationInterval configures the interval between monitor
	// messages when monitor aggregation is enabled.
	MonitorAggregationInterval time.Duration

	// MonitorAggregationFlags determines which TCP flags that the monitor
	// aggregation ensures reports are generated for when monitor-aggragation
	// is enabled. Network byte-order.
	MonitorAggregationFlags uint16

	// BPFEventsDefaultRateLimit specifies limit of messages per second that can be written to
	// BPF events map. This limit is defined for all types of events except dbg and pcap.
	// The number of messages is averaged, meaning that if no messages were written
	// to the map over 5 seconds, it's possible to write more events than the value of rate limit
	// in the 6th second.
	//
	// If BPFEventsDefaultRateLimit > 0, non-zero value for BPFEventsDefaultBurstLimit must also be provided
	// lest the configuration is considered invalid.
	BPFEventsDefaultRateLimit uint32

	// BPFEventsDefaultBurstLimit specifies the maximum number of messages that can be written
	// to BPF events map in 1 second. This limit is defined for all types of events except dbg and pcap.
	//
	// If BPFEventsDefaultBurstLimit > 0, non-zero value for BPFEventsDefaultRateLimit must also be provided
	// lest the configuration is considered invalid.
	// If both burst and rate limit are 0 or not specified, no limit is imposed.
	BPFEventsDefaultBurstLimit uint32

	// BPFMapsDynamicSizeRatio is ratio of total system memory to use for
	// dynamic sizing of the CT, NAT, Neighbor and SockRevNAT BPF maps.
	BPFMapsDynamicSizeRatio float64

	// NATMapEntriesGlobal is the maximum number of NAT mappings allowed
	// in the BPF NAT table
	NATMapEntriesGlobal int

	// NeighMapEntriesGlobal is the maximum number of neighbor mappings
	// allowed in the BPF neigh table
	NeighMapEntriesGlobal int

	// AuthMapEntries is the maximum number of entries in the auth map.
	AuthMapEntries int

	// PolicyMapEntries is the maximum number of peer identities that an
	// endpoint may allow traffic to exchange traffic with.
	PolicyMapEntries int

	// PolicyMapFullReconciliationInterval is the interval at which to perform
	// the full reconciliation of the endpoint policy map.
	PolicyMapFullReconciliationInterval time.Duration

	// SockRevNatEntries is the maximum number of sock rev nat mappings
	// allowed in the BPF rev nat table
	SockRevNatEntries int

	// DisableCiliumEndpointCRD disables the use of CiliumEndpoint CRD
	DisableCiliumEndpointCRD bool

	// MaxControllerInterval is the maximum value for a controller's
	// RunInterval. Zero means unlimited.
	MaxControllerInterval int

	// HTTP403Message is the error message to return when a HTTP 403 is returned
	// by the proxy, if L7 policy is configured.
	HTTP403Message string

	ProcFs string

	// K8sNamespace is the name of the namespace in which Cilium is
	// deployed in when running in Kubernetes mode
	K8sNamespace string

	// AgentNotReadyNodeTaint is a node taint which prevents pods from being
	// scheduled. Once cilium is setup it is removed from the node. Mostly
	// used in cloud providers to prevent existing CNI plugins from managing
	// pods.
	AgentNotReadyNodeTaintKey string

	// JoinCluster is 'true' if the agent should join a Cilium cluster via kvstore
	// registration
	JoinCluster bool

	// EnableIPv4 is true when IPv4 is enabled
	EnableIPv4 bool

	// EnableIPv6 is true when IPv6 is enabled
	EnableIPv6 bool

	// EnableNat46X64Gateway is true when L3 based NAT46 and NAT64 translation is enabled
	EnableNat46X64Gateway bool

	// EnableIPv6NDP is true when NDP is enabled for IPv6
	EnableIPv6NDP bool

	// EnableSRv6 is true when SRv6 encapsulation support is enabled
	EnableSRv6 bool

	// SRv6EncapMode is the encapsulation mode for SRv6
	SRv6EncapMode string

	// EnableSCTP is true when SCTP support is enabled.
	EnableSCTP bool

	// IPv6MCastDevice is the name of device that joins IPv6's solicitation multicast group
	IPv6MCastDevice string

	// EnableL7Proxy is the option to enable L7 proxy
	EnableL7Proxy bool

	// EnableIPSec is true when IPSec is enabled
	EnableIPSec bool

	// IPSec key file for stored keys
	IPSecKeyFile string

	// Duration of the IPsec key rotation. After that time, we will clean the
	// previous IPsec key from the node.
	IPsecKeyRotationDuration time.Duration

	// Enable watcher for IPsec key. If disabled, a restart of the agent will
	// be necessary on key rotations.
	EnableIPsecKeyWatcher bool

	// EnableIPSecXfrmStateCaching enables IPSec XfrmState caching.
	EnableIPSecXfrmStateCaching bool

	// EnableIPSecEncryptedOverlay enables IPSec encryption for overlay traffic.
	EnableIPSecEncryptedOverlay bool

	// EnableWireguard enables Wireguard encryption
	EnableWireguard bool

	// EnableEncryptionStrictMode enables strict mode for encryption
	EnableEncryptionStrictMode bool

	// EncryptionStrictModeCIDR is the CIDR to use for strict mode
	EncryptionStrictModeCIDR netip.Prefix

	// EncryptionStrictModeAllowRemoteNodeIdentities allows dynamic lookup of node identities.
	// This is required when tunneling is used
	// or direct routing is used and the node CIDR and pod CIDR overlap.
	EncryptionStrictModeAllowRemoteNodeIdentities bool

	// EnableWireguardUserspaceFallback enables the fallback to the userspace implementation
	EnableWireguardUserspaceFallback bool

	// WireguardPersistentKeepalive controls Wireguard PersistentKeepalive option.
	WireguardPersistentKeepalive time.Duration

	// EnableL2Announcements enables L2 announcement of service IPs
	EnableL2Announcements bool

	// L2AnnouncerLeaseDuration, if a lease has not been renewed for X amount of time, a new leader can be chosen.
	L2AnnouncerLeaseDuration time.Duration
	// L2AnnouncerRenewDeadline, the leader will renew the lease every X amount of time.
	L2AnnouncerRenewDeadline time.Duration
	// L2AnnouncerRetryPeriod, on renew failure, retry after X amount of time.
	L2AnnouncerRetryPeriod time.Duration

	// NodeEncryptionOptOutLabels contains the label selectors for nodes opting out of
	// node-to-node encryption
	// This field ignored when marshalling to JSON in DaemonConfig.StoreInFile,
	// because a k8sLabels.Selector cannot be unmarshalled from JSON. The
	// string is stored in NodeEncryptionOptOutLabelsString instead.
	NodeEncryptionOptOutLabels k8sLabels.Selector `json:"-"`
	// NodeEncryptionOptOutLabelsString is the string is used to construct
	// the label selector in the above field.
	NodeEncryptionOptOutLabelsString string

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
	EnableSocketLB                bool
	EnableSocketLBTracing         bool
	EnableSocketLBPeer            bool
	EnablePolicy                  string
	EnableTracing                 bool
	EnableIPIPTermination         bool
	EnableUnreachableRoutes       bool
	FixedIdentityMapping          map[string]string
	FixedIdentityMappingValidator func(val string) (string, error) `json:"-"`
	FixedZoneMapping              map[string]uint8
	ReverseFixedZoneMapping       map[uint8]string
	FixedZoneMappingValidator     func(val string) (string, error) `json:"-"`
	IPv4Range                     string
	IPv6Range                     string
	IPv4ServiceRange              string
	IPv6ServiceRange              string
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
	EnableIPv4Masquerade        bool
	EnableIPv6Masquerade        bool
	EnableBPFMasquerade         bool
	EnableMasqueradeRouteSource bool
	EnableIPMasqAgent           bool
	IPMasqAgentConfigPath       string

	EnableBPFClockProbe     bool
	EnableIPv4EgressGateway bool
	EnableEnvoyConfig       bool
	InstallIptRules         bool
	MonitorAggregation      string
	PreAllocateMaps         bool
	IPv6NodeAddr            string
	IPv4NodeAddr            string
	SocketPath              string
	TracePayloadlen         int
	Version                 string
	PrometheusServeAddr     string
	ToFQDNsMinTTL           int

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

	// FQDNRegexCompileLRUSize is the size of the FQDN regex compilation LRU.
	// Useful for heavy but repeated FQDN MatchName or MatchPattern use.
	FQDNRegexCompileLRUSize int

	// Path to a file with DNS cache data to preload on startup
	ToFQDNsPreCache string

	// ToFQDNsEnableDNSCompression allows the DNS proxy to compress responses to
	// endpoints that are larger than 512 Bytes or the EDNS0 option, if present.
	ToFQDNsEnableDNSCompression bool

	// DNSProxyConcurrencyLimit limits parallel processing of DNS messages in
	// DNS proxy at any given point in time.
	DNSProxyConcurrencyLimit int

	// DNSProxyConcurrencyProcessingGracePeriod is the amount of grace time to
	// wait while processing DNS messages when the DNSProxyConcurrencyLimit has
	// been reached.
	DNSProxyConcurrencyProcessingGracePeriod time.Duration

	// DNSProxyEnableTransparentMode enables transparent mode for the DNS proxy.
	DNSProxyEnableTransparentMode bool

	// DNSProxyInsecureSkipTransparentModeCheck is a hidden flag that allows users
	// to disable transparent mode even if IPSec is enabled
	DNSProxyInsecureSkipTransparentModeCheck bool

	// DNSProxyLockCount is the array size containing mutexes which protect
	// against parallel handling of DNS response names.
	DNSProxyLockCount int

	// DNSProxyLockTimeout is timeout when acquiring the locks controlled by
	// DNSProxyLockCount.
	DNSProxyLockTimeout time.Duration

	// DNSProxySocketLingerTimeout defines how many seconds we wait for the connection
	// between the DNS proxy and the upstream server to be closed.
	DNSProxySocketLingerTimeout int

	// EnableXTSocketFallback allows disabling of kernel's ip_early_demux
	// sysctl option if `xt_socket` kernel module is not available.
	EnableXTSocketFallback bool

	// EnableBPFTProxy enables implementing proxy redirection via BPF
	// mechanisms rather than iptables rules.
	EnableBPFTProxy bool

	// EnableAutoDirectRouting enables installation of direct routes to
	// other nodes when available
	EnableAutoDirectRouting bool

	// DirectRoutingSkipUnreachable skips installation of direct routes
	// to nodes when they're not on the same L2
	DirectRoutingSkipUnreachable bool

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

	// EnableHealthCheckLoadBalancerIP enables health checking of LoadBalancerIP
	// by cilium
	EnableHealthCheckLoadBalancerIP bool

	// KVstoreKeepAliveInterval is the interval in which the lease is being
	// renewed. This must be set to a value lesser than the LeaseTTL ideally
	// by a factor of 3.
	KVstoreKeepAliveInterval time.Duration

	// KVstoreLeaseTTL is the time-to-live for kvstore lease.
	KVstoreLeaseTTL time.Duration

	// KVstoreMaxConsecutiveQuorumErrors is the maximum number of acceptable
	// kvstore consecutive quorum errors before the agent assumes permanent failure
	KVstoreMaxConsecutiveQuorumErrors uint

	// KVstorePeriodicSync is the time interval in which periodic
	// synchronization with the kvstore occurs
	KVstorePeriodicSync time.Duration

	// KVstoreConnectivityTimeout is the timeout when performing kvstore operations
	KVstoreConnectivityTimeout time.Duration

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
	//
	// The default is 30 seconds for k8s clusters, and 10 minutes for kvstore clusters
	IdentityRestoreGracePeriod time.Duration

	// PolicyQueueSize is the size of the queues for the policy repository.
	// A larger queue means that more events related to policy can be buffered.
	PolicyQueueSize int

	// EndpointQueueSize is the size of the EventQueue per-endpoint. A larger
	// queue means that more events can be buffered per-endpoint. This is useful
	// in the case where a cluster might be under high load for endpoint-related
	// events, specifically those which cause many regenerations.
	EndpointQueueSize int

	// ConntrackGCInterval is the connection tracking garbage collection
	// interval
	ConntrackGCInterval time.Duration

	// ConntrackGCMaxInterval if set limits the automatic GC interval calculation to
	// the specified maximum value.
	ConntrackGCMaxInterval time.Duration

	// LoopbackIPv4 is the address to use for service loopback SNAT
	LoopbackIPv4 string

	// LocalRouterIPv4 is the link-local IPv4 address used for Cilium's router device
	LocalRouterIPv4 string

	// LocalRouterIPv6 is the link-local IPv6 address used for Cilium's router device
	LocalRouterIPv6 string

	// EnableEndpointRoutes enables use of per endpoint routes
	EnableEndpointRoutes bool

	// Specifies wheather to annotate the kubernetes nodes or not
	AnnotateK8sNode bool

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

	// LoadBalancerExternalControlPlane tells whether to not use kube-apiserver as
	// its control plane in lb-only mode.
	LoadBalancerExternalControlPlane bool

	// EnablePMTUDiscovery indicates whether to send ICMP fragmentation-needed
	// replies to the client (when needed).
	EnablePMTUDiscovery bool

	// Maglev backend table size (M) per service. Must be prime number.
	MaglevTableSize int

	// MaglevHashSeed contains the cluster-wide seed for the hash(es).
	MaglevHashSeed string

	// NodePortAcceleration indicates whether NodePort should be accelerated
	// via XDP ("none", "generic", "native", or "best-effort")
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

	// AddressScopeMax controls the maximum address scope for addresses to be
	// considered local ones with HOST_ID in the ipcache
	AddressScopeMax int

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

	// NodePortMin is the minimum port address for the NodePort range
	NodePortMin int

	// NodePortMax is the maximum port address for the NodePort range
	NodePortMax int

	// EnableSessionAffinity enables a support for service sessionAffinity
	EnableSessionAffinity bool

	// Selection of BPF main clock source (ktime vs jiffies)
	ClockSource BPFClockSource

	// EnableIdentityMark enables setting the mark field with the identity for
	// local traffic. This may be disabled if chaining modes and Cilium use
	// conflicting marks.
	EnableIdentityMark bool

	// EnableHighScaleIPcache enables the special ipcache mode for high scale
	// clusters. The ipcache content will be reduced to the strict minimum and
	// traffic will be encapsulated to carry security identities.
	EnableHighScaleIPcache bool

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

	// IPAMMultiPoolPreAllocation defines the pre-allocation value for each IPAM pool
	IPAMMultiPoolPreAllocation map[string]string
	// IPAMDefaultIPPool the default IP Pool when using multi-pool
	IPAMDefaultIPPool string
	// AutoCreateCiliumNodeResource enables automatic creation of a
	// CiliumNode resource for the local node
	AutoCreateCiliumNodeResource bool

	// ExcludeNodeLabelPatterns allows for excluding unnecessary labels from being propagated from k8s node to cilium
	// node object. This allows for avoiding unnecessary events being broadcast to all nodes in the cluster.
	ExcludeNodeLabelPatterns []*regexp.Regexp

	// IPv4NativeRoutingCIDR describes a CIDR in which pod IPs are routable
	IPv4NativeRoutingCIDR *cidr.CIDR

	// IPv6NativeRoutingCIDR describes a CIDR in which pod IPs are routable
	IPv6NativeRoutingCIDR *cidr.CIDR

	// MasqueradeInterfaces is the selector used to select interfaces subject
	// to egress masquerading. EgressMasqueradeInterfaces is the same but as
	// a string representation. It's deprecated and can be removed once the GH
	// issue https://github.com/cilium/cilium-cli/issues/1896 is fixed.
	MasqueradeInterfaces       []string
	EgressMasqueradeInterfaces string

	// PolicyTriggerInterval is the amount of time between when policy updates
	// are triggered.
	PolicyTriggerInterval time.Duration

	// IdentityAllocationMode specifies what mode to use for identity
	// allocation
	IdentityAllocationMode string

	// AllowICMPFragNeeded allows ICMP Fragmentation Needed type packets in
	// the network policy for cilium-agent.
	AllowICMPFragNeeded bool

	// EnableWellKnownIdentities enables the use of well-known identities.
	// This is requires if identiy resolution is required to bring up the
	// control plane, e.g. when using the managed etcd feature
	EnableWellKnownIdentities bool

	// Azure options

	// PolicyAuditMode enables non-drop mode for installed policies. In
	// audit mode packets affected by policies will not be dropped.
	// Policy related decisions can be checked via the poicy verdict messages.
	PolicyAuditMode bool

	// PolicyAccounting enable policy accounting
	PolicyAccounting bool

	// EnableHubble specifies whether to enable the hubble server.
	EnableHubble bool

	// HubbleSocketPath specifies the UNIX domain socket for Hubble server to listen to.
	HubbleSocketPath string

	// HubbleListenAddress specifies address for Hubble to listen to.
	HubbleListenAddress string

	// HubblePreferIpv6 controls whether IPv6 or IPv4 addresses should be preferred for
	// communication to agents, if both are available.
	HubblePreferIpv6 bool

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

	// HubbleMetricsServerTLSEnabled allows the Hubble metrics server to run on the given listen
	// address with TLS.
	HubbleMetricsServerTLSEnabled bool

	// HubbleMetricsServerTLSCertFile specifies the path to the public key file for the
	// Hubble server. The file must contain PEM encoded data.
	HubbleMetricsServerTLSCertFile string

	// HubbleMetricsServerTLSKeyFile specifies the path to the private key file for the
	// Hubble server. The file must contain PEM encoded data.
	HubbleMetricsServerTLSKeyFile string

	// HubbleMetricsServerTLSClientCAFiles specifies the path to one or more client CA
	// certificates to use for TLS with mutual authentication (mTLS). The files
	// must contain PEM encoded data.
	HubbleMetricsServerTLSClientCAFiles []string

	// HubbleMetrics specifies enabled metrics and their configuration options.
	HubbleMetrics []string

	// HubbleFlowlogsConfigFilePath specifies the filepath with configuration of hubble flowlogs.
	// e.g. "/etc/cilium/flowlog.yaml"
	HubbleFlowlogsConfigFilePath string

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

	// HubbleExportAllowlist specifies allow list filter use by exporter.
	HubbleExportAllowlist []*flowpb.FlowFilter

	// HubbleExportDenylist specifies deny list filter use by exporter.
	HubbleExportDenylist []*flowpb.FlowFilter

	// HubbleExportFieldmask specifies list of fields to log in exporter.
	HubbleExportFieldmask []string

	// EnableHubbleRecorderAPI specifies if the Hubble Recorder API should be served
	EnableHubbleRecorderAPI bool

	// EnableHubbleOpenMetrics enables exporting hubble metrics in OpenMetrics format.
	EnableHubbleOpenMetrics bool

	// HubbleRecorderStoragePath specifies the directory in which pcap files
	// created via the Hubble Recorder API are stored
	HubbleRecorderStoragePath string

	// HubbleRecorderSinkQueueSize is the queue size for each recorder sink
	HubbleRecorderSinkQueueSize int

	// HubbleSkipUnknownCGroupIDs specifies if events with unknown cgroup ids should be skipped
	HubbleSkipUnknownCGroupIDs bool

	// HubbleMonitorEvents specifies Cilium monitor events for Hubble to observe.
	// By default, Hubble observes all monitor events.
	HubbleMonitorEvents []string

	// HubbleRedactEnabled controls if Hubble will be redacting sensitive information from L7 flows
	HubbleRedactEnabled bool

	// HubbleRedactURLQuery controls if the URL query will be redacted from flows
	HubbleRedactHttpURLQuery bool

	// HubbleRedactUserInfo controls if the user info will be redacted from flows
	HubbleRedactHttpUserInfo bool

	// HubbleRedactKafkaApiKey controls if Kafka API key will be redacted from flows
	HubbleRedactKafkaApiKey bool

	// HubbleRedactHttpHeadersAllow controls which http headers will not be redacted from flows
	HubbleRedactHttpHeadersAllow []string

	// HubbleRedactHttpHeadersDeny controls which http headers will be redacted from flows
	HubbleRedactHttpHeadersDeny []string

	// HubbleDropEvents controls whether Hubble should create v1.Events
	// for packet drops related to pods
	HubbleDropEvents bool

	// HubbleDropEventsInterval controls the minimum time between emitting events
	// with the same source and destination IP
	HubbleDropEventsInterval time.Duration

	// HubbleDropEventsReasons controls which drop reasons to emit events for
	HubbleDropEventsReasons []string

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

	// CRDWaitTimeout is the timeout in which Cilium will exit if CRDs are not
	// available.
	CRDWaitTimeout time.Duration

	// EgressMultiHomeIPRuleCompat instructs Cilium to use a new scheme to
	// store rules and routes under ENI and Azure IPAM modes, if false.
	// Otherwise, it will use the old scheme.
	EgressMultiHomeIPRuleCompat bool

	// InstallNoConntrackIptRules instructs Cilium to install Iptables rules to skip netfilter connection tracking on all pod traffic.
	InstallNoConntrackIptRules bool

	// ContainerIPLocalReservedPorts instructs the Cilium CNI plugin to reserve
	// the provided comma-separated list of ports in the container network namespace
	ContainerIPLocalReservedPorts string

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

	// BGPSecretsNamespace is the Kubernetes namespace to get BGP control plane secrets from.
	BGPSecretsNamespace string

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

	// DisableExternalIPMigration disable externalIP mitigation (CVE-2020-8554)
	DisableExternalIPMitigation bool

	// EnableL2NeighDiscovery determines if cilium should perform L2 neighbor
	// discovery.
	EnableL2NeighDiscovery bool

	// EnableICMPRules enables ICMP-based rule support for Cilium Network Policies.
	EnableICMPRules bool

	// Use the CiliumInternalIPs (vs. NodeInternalIPs) for IPsec encapsulation.
	UseCiliumInternalIPForIPsec bool

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
	TCFilterPriority uint16

	// Enables BGP control plane features.
	EnableBGPControlPlane bool

	// BPFMapEventBuffers has configuration on what BPF map event buffers to enabled
	// and configuration options for those.
	BPFMapEventBuffers          map[string]string
	BPFMapEventBuffersValidator func(val string) (string, error) `json:"-"`
	bpfMapEventConfigs          BPFEventBufferConfigs

	// BPFEventsDropEnabled controls whether the Cilium datapath exposes "drop" events to Cilium monitor and Hubble.
	BPFEventsDropEnabled bool

	// BPFEventsPolicyVerdictEnabled controls whether the Cilium datapath exposes "policy verdict" events to Cilium monitor and Hubble.
	BPFEventsPolicyVerdictEnabled bool

	// BPFEventsTraceEnabled  controls whether the Cilium datapath exposes "trace" events to Cilium monitor and Hubble.
	BPFEventsTraceEnabled bool

	// IPAMCiliumNodeUpdateRate is the maximum rate at which the CiliumNode custom
	// resource is updated.
	IPAMCiliumNodeUpdateRate time.Duration

	// EnableK8sNetworkPolicy enables support for K8s NetworkPolicy.
	EnableK8sNetworkPolicy bool

	// PolicyCIDRMatchMode is the list of entities that can be selected by CIDR policy.
	// Currently supported values:
	// - world
	// - world, remote-node
	PolicyCIDRMatchMode []string

	// MaxConnectedClusters sets the maximum number of clusters that can be
	// connected in a clustermesh.
	// The value is used to determine the bit allocation for cluster ID and
	// identity in a numeric identity. Values > 255 will decrease the number of
	// allocatable identities.
	MaxConnectedClusters uint32

	// ForceDeviceRequired enforces the attachment of BPF programs on native device.
	ForceDeviceRequired bool

	// ServiceNoBackendResponse determines how we handle traffic to a service with no backends.
	ServiceNoBackendResponse string

	// EnableNodeSelectorLabels enables use of the node label based identity
	EnableNodeSelectorLabels bool

	// NodeLabels is the list of label prefixes used to determine identity of a node (requires enabling of
	// EnableNodeSelectorLabels)
	NodeLabels []string
}

var (
	// Config represents the daemon configuration
	Config = &DaemonConfig{
		CreationTime:                    time.Now(),
		Opts:                            NewIntOptions(&DaemonOptionLibrary),
		ConfigPatchMutex:                new(lock.RWMutex),
		Monitor:                         &models.MonitorStatus{Cpus: int64(runtime.NumCPU()), Npages: 64, Pagesize: int64(os.Getpagesize()), Lost: 0, Unknown: 0},
		IPv6ClusterAllocCIDR:            defaults.IPv6ClusterAllocCIDR,
		IPv6ClusterAllocCIDRBase:        defaults.IPv6ClusterAllocCIDRBase,
		IPAMDefaultIPPool:               defaults.IPAMDefaultIPPool,
		EnableHealthChecking:            defaults.EnableHealthChecking,
		EnableEndpointHealthChecking:    defaults.EnableEndpointHealthChecking,
		EnableHealthCheckLoadBalancerIP: defaults.EnableHealthCheckLoadBalancerIP,
		EnableHealthCheckNodePort:       defaults.EnableHealthCheckNodePort,
		EnableIPv4:                      defaults.EnableIPv4,
		EnableIPv6:                      defaults.EnableIPv6,
		EnableIPv6NDP:                   defaults.EnableIPv6NDP,
		EnableSCTP:                      defaults.EnableSCTP,
		EnableL7Proxy:                   defaults.EnableL7Proxy,
		DNSMaxIPsPerRestoredRule:        defaults.DNSMaxIPsPerRestoredRule,
		ToFQDNsMaxIPsPerHost:            defaults.ToFQDNsMaxIPsPerHost,
		KVstorePeriodicSync:             defaults.KVstorePeriodicSync,
		KVstoreConnectivityTimeout:      defaults.KVstoreConnectivityTimeout,
		IdentityChangeGracePeriod:       defaults.IdentityChangeGracePeriod,
		IdentityRestoreGracePeriod:      defaults.IdentityRestoreGracePeriodK8s,
		FixedIdentityMapping:            make(map[string]string),
		KVStoreOpt:                      make(map[string]string),
		LogOpt:                          make(map[string]string),
		LoopbackIPv4:                    defaults.LoopbackIPv4,
		EnableEndpointRoutes:            defaults.EnableEndpointRoutes,
		AnnotateK8sNode:                 defaults.AnnotateK8sNode,
		K8sServiceCacheSize:             defaults.K8sServiceCacheSize,
		AutoCreateCiliumNodeResource:    defaults.AutoCreateCiliumNodeResource,
		IdentityAllocationMode:          IdentityAllocationModeKVstore,
		AllowICMPFragNeeded:             defaults.AllowICMPFragNeeded,
		EnableWellKnownIdentities:       defaults.EnableWellKnownIdentities,
		AllocatorListTimeout:            defaults.AllocatorListTimeout,
		EnableICMPRules:                 defaults.EnableICMPRules,
		UseCiliumInternalIPForIPsec:     defaults.UseCiliumInternalIPForIPsec,

		K8sEnableLeasesFallbackDiscovery: defaults.K8sEnableLeasesFallbackDiscovery,

		ExternalClusterIP:      defaults.ExternalClusterIP,
		EnableVTEP:             defaults.EnableVTEP,
		EnableBGPControlPlane:  defaults.EnableBGPControlPlane,
		EnableK8sNetworkPolicy: defaults.EnableK8sNetworkPolicy,
		PolicyCIDRMatchMode:    defaults.PolicyCIDRMatchMode,
		MaxConnectedClusters:   defaults.MaxConnectedClusters,

		BPFEventsDropEnabled:          defaults.BPFEventsDropEnabled,
		BPFEventsPolicyVerdictEnabled: defaults.BPFEventsPolicyVerdictEnabled,
		BPFEventsTraceEnabled:         defaults.BPFEventsTraceEnabled,
		EnableEnvoyConfig:             defaults.EnableEnvoyConfig,
	}
)

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

// TunnelingEnabled returns true if tunneling is enabled.
func (c *DaemonConfig) TunnelingEnabled() bool {
	// We check if routing mode is not native rather than checking if it's
	// tunneling because, in unit tests, RoutingMode is usually not set and we
	// would like for TunnelingEnabled to default to the actual default
	// (tunneling is enabled) in that case.
	return c.RoutingMode != RoutingModeNative
}

// AreDevicesRequired returns true if the agent needs to attach to the native
// devices to implement some features.
func (c *DaemonConfig) AreDevicesRequired() bool {
	return c.EnableNodePort || c.EnableHostFirewall || c.EnableWireguard ||
		c.EnableHighScaleIPcache || c.EnableL2Announcements || c.ForceDeviceRequired ||
		c.EnableIPSecEncryptedOverlay
}

// When WG & encrypt-node are on, a NodePort BPF to-be forwarded request
// to a remote node running a selected service endpoint must be encrypted.
// To make the NodePort's rev-{S,D}NAT translations to happen for a reply
// from the remote node, we need to attach bpf_host to the Cilium's WG
// netdev (otherwise, the WG netdev after decrypting the reply will pass
// it to the stack which drops the packet).
func (c *DaemonConfig) NeedBPFHostOnWireGuardDevice() bool {
	return c.EnableNodePort && c.EnableWireguard && c.EncryptNode
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
	return !c.TunnelingEnabled() && c.IptablesMasqueradingEnabled()
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

// SCTPEnabled returns true if SCTP support is enabled
func (c *DaemonConfig) SCTPEnabled() bool {
	return c.EnableSCTP
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

// CiliumNamespaceName returns the name of the namespace in which Cilium is
// deployed in
func (c *DaemonConfig) CiliumNamespaceName() string {
	return c.K8sNamespace
}

// AgentNotReadyNodeTaintValue returns the value of the taint key that cilium agents
// will manage on their nodes
func (c *DaemonConfig) AgentNotReadyNodeTaintValue() string {
	if c.AgentNotReadyNodeTaintKey != "" {
		return c.AgentNotReadyNodeTaintKey
	} else {
		return defaults.AgentNotReadyNodeTaint
	}
}

// K8sNetworkPolicyEnabled returns true if cilium agent needs to support K8s NetworkPolicy, false otherwise.
func (c *DaemonConfig) K8sNetworkPolicyEnabled() bool {
	return c.EnableK8sNetworkPolicy
}

func (c *DaemonConfig) PolicyCIDRMatchesNodes() bool {
	for _, mode := range c.PolicyCIDRMatchMode {
		if mode == "nodes" {
			return true
		}
	}
	return false
}

// PerNodeLabelsEnabled returns true if per-node labels feature
// is enabled
func (c *DaemonConfig) PerNodeLabelsEnabled() bool {
	return c.EnableNodeSelectorLabels
}

func (c *DaemonConfig) validatePolicyCIDRMatchMode() error {
	// Currently, the only acceptable values is "nodes".
	for _, mode := range c.PolicyCIDRMatchMode {
		switch mode {
		case "nodes":
			continue
		default:
			return fmt.Errorf("unknown CIDR match mode: %s", mode)
		}
	}
	return nil
}

// DirectRoutingDeviceRequired return whether the Direct Routing Device is needed under
// the current configuration.
func (c *DaemonConfig) DirectRoutingDeviceRequired() bool {
	// BPF NodePort and BPF Host Routing are using the direct routing device now.
	// When tunneling is enabled, node-to-node redirection will be done by tunneling.
	BPFHostRoutingEnabled := !c.EnableHostLegacyRouting

	// XDP needs IPV4_DIRECT_ROUTING when building tunnel headers:
	if c.EnableNodePort && c.NodePortAcceleration != NodePortAccelerationDisabled {
		return true
	}

	return c.EnableNodePort || BPFHostRoutingEnabled || Config.EnableWireguard
}

func (c *DaemonConfig) LoadBalancerUsesDSR() bool {
	return c.NodePortMode == NodePortModeDSR ||
		c.NodePortMode == NodePortModeHybrid
}

func (c *DaemonConfig) validateIPv6ClusterAllocCIDR() error {
	ip, cidr, err := net.ParseCIDR(c.IPv6ClusterAllocCIDR)
	if err != nil {
		return err
	}

	if ones, _ := cidr.Mask.Size(); ones != 64 {
		return fmt.Errorf("Prefix length must be /64")
	}

	c.IPv6ClusterAllocCIDRBase = ip.Mask(cidr.Mask).String()

	return nil
}

func (c *DaemonConfig) validateIPv6NAT46x64CIDR() error {
	parsedPrefix, err := netip.ParsePrefix(c.IPv6NAT46x64CIDR)
	if err != nil {
		return err
	}
	if parsedPrefix.Bits() != 96 {
		return fmt.Errorf("Prefix length must be /96")
	}

	c.IPv6NAT46x64CIDRBase = parsedPrefix.Masked().Addr()
	return nil
}

func (c *DaemonConfig) validateHubbleRedact() error {
	if len(c.HubbleRedactHttpHeadersAllow) > 0 && len(c.HubbleRedactHttpHeadersDeny) > 0 {
		return fmt.Errorf("Only one of --hubble-redact-http-headers-allow and --hubble-redact-http-headers-deny can be specified, not both")
	}
	return nil
}

func (c *DaemonConfig) validateContainerIPLocalReservedPorts() error {
	if c.ContainerIPLocalReservedPorts == "" || c.ContainerIPLocalReservedPorts == defaults.ContainerIPLocalReservedPortsAuto {
		return nil
	}

	if regexp.MustCompile(`^(\d+(-\d+)?)(,\d+(-\d+)?)*$`).MatchString(c.ContainerIPLocalReservedPorts) {
		return nil
	}

	return fmt.Errorf("Invalid comma separated list of of ranges for %s option", ContainerIPLocalReservedPorts)
}

// Validate validates the daemon configuration
func (c *DaemonConfig) Validate(vp *viper.Viper) error {
	if err := c.validateIPv6ClusterAllocCIDR(); err != nil {
		return fmt.Errorf("unable to parse CIDR value '%s' of option --%s: %w",
			c.IPv6ClusterAllocCIDR, IPv6ClusterAllocCIDRName, err)
	}

	if err := c.validateIPv6NAT46x64CIDR(); err != nil {
		return fmt.Errorf("unable to parse internal CIDR value '%s': %w",
			c.IPv6NAT46x64CIDR, err)
	}

	if err := c.validateHubbleRedact(); err != nil {
		return err
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
		if len(c.IPv6MCastDevice) == 0 {
			return fmt.Errorf("IPv6NDP cannot be enabled without %s", IPv6MCastDevice)
		}
	}

	switch c.RoutingMode {
	case RoutingModeNative, RoutingModeTunnel:
	default:
		return fmt.Errorf("invalid routing mode %q, valid modes = {%q, %q}",
			c.RoutingMode, RoutingModeTunnel, RoutingModeNative)
	}

	cinfo := clustermeshTypes.ClusterInfo{
		ID:                   c.ClusterID,
		Name:                 c.ClusterName,
		MaxConnectedClusters: c.MaxConnectedClusters,
	}
	if err := cinfo.InitClusterIDMax(); err != nil {
		return err
	}
	if err := cinfo.Validate(log); err != nil {
		return err
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

	if err := c.checkIPAMDelegatedPlugin(); err != nil {
		return err
	}

	// Validate that the KVStore Lease TTL value lies between a particular range.
	if c.KVstoreLeaseTTL > defaults.KVstoreLeaseMaxTTL || c.KVstoreLeaseTTL < defaults.LockLeaseTTL {
		return fmt.Errorf("KVstoreLeaseTTL does not lie in required range(%ds, %ds)",
			int64(defaults.LockLeaseTTL.Seconds()),
			int64(defaults.KVstoreLeaseMaxTTL.Seconds()))
	}

	if c.EnableVTEP {
		err := c.validateVTEP(vp)
		if err != nil {
			return fmt.Errorf("Failed to validate VTEP configuration: %w", err)
		}
	}

	if err := c.validatePolicyCIDRMatchMode(); err != nil {
		return err
	}

	if err := c.validateContainerIPLocalReservedPorts(); err != nil {
		return err
	}

	return nil
}

// ReadDirConfig reads the given directory and returns a map that maps the
// filename to the contents of that file.
func ReadDirConfig(dirName string) (map[string]interface{}, error) {
	m := map[string]interface{}{}
	files, err := os.ReadDir(dirName)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to read configuration directory: %w", err)
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
func MergeConfig(vp *viper.Viper, m map[string]interface{}) error {
	err := vp.MergeConfigMap(m)
	if err != nil {
		return fmt.Errorf("unable to read merge directory configuration: %w", err)
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
			return fmt.Errorf("unable to parse excluded local address %s: %w", ipString, err)
		}

		c.ExcludeLocalAddresses = append(c.ExcludeLocalAddresses, ipnet)
	}

	return nil
}

// Populate sets all options with the values from viper
func (c *DaemonConfig) Populate(vp *viper.Viper) {
	var err error

	c.AgentHealthPort = vp.GetInt(AgentHealthPort)
	c.ClusterHealthPort = vp.GetInt(ClusterHealthPort)
	c.ClusterMeshHealthPort = vp.GetInt(ClusterMeshHealthPort)
	c.AgentLabels = vp.GetStringSlice(AgentLabels)
	c.AllowICMPFragNeeded = vp.GetBool(AllowICMPFragNeeded)
	c.AllowLocalhost = vp.GetString(AllowLocalhost)
	c.AnnotateK8sNode = vp.GetBool(AnnotateK8sNode)
	c.ARPPingRefreshPeriod = vp.GetDuration(ARPPingRefreshPeriod)
	c.EnableL2NeighDiscovery = vp.GetBool(EnableL2NeighDiscovery)
	c.AutoCreateCiliumNodeResource = vp.GetBool(AutoCreateCiliumNodeResource)
	c.BPFRoot = vp.GetString(BPFRoot)
	c.CGroupRoot = vp.GetString(CGroupRoot)
	c.ClusterID = vp.GetUint32(clustermeshTypes.OptClusterID)
	c.ClusterName = vp.GetString(clustermeshTypes.OptClusterName)
	c.MaxConnectedClusters = vp.GetUint32(clustermeshTypes.OptMaxConnectedClusters)
	c.DatapathMode = vp.GetString(DatapathMode)
	c.Debug = vp.GetBool(DebugArg)
	c.DebugVerbose = vp.GetStringSlice(DebugVerbose)
	c.DirectRoutingDevice = vp.GetString(DirectRoutingDevice)
	c.EnableIPv4 = vp.GetBool(EnableIPv4Name)
	c.EnableIPv6 = vp.GetBool(EnableIPv6Name)
	c.EnableIPv6NDP = vp.GetBool(EnableIPv6NDPName)
	c.EnableSRv6 = vp.GetBool(EnableSRv6)
	c.SRv6EncapMode = vp.GetString(SRv6EncapModeName)
	c.EnableSCTP = vp.GetBool(EnableSCTPName)
	c.IPv6MCastDevice = vp.GetString(IPv6MCastDevice)
	c.EnableIPSec = vp.GetBool(EnableIPSecName)
	c.EnableWireguard = vp.GetBool(EnableWireguard)
	c.EnableL2Announcements = vp.GetBool(EnableL2Announcements)
	c.L2AnnouncerLeaseDuration = vp.GetDuration(L2AnnouncerLeaseDuration)
	c.L2AnnouncerRenewDeadline = vp.GetDuration(L2AnnouncerRenewDeadline)
	c.L2AnnouncerRetryPeriod = vp.GetDuration(L2AnnouncerRetryPeriod)
	c.EnableWireguardUserspaceFallback = vp.GetBool(EnableWireguardUserspaceFallback)
	c.WireguardPersistentKeepalive = vp.GetDuration(WireguardPersistentKeepalive)
	c.EnableWellKnownIdentities = vp.GetBool(EnableWellKnownIdentities)
	c.EnableXDPPrefilter = vp.GetBool(EnableXDPPrefilter)
	c.EnableTCX = vp.GetBool(EnableTCX)
	c.DisableCiliumEndpointCRD = vp.GetBool(DisableCiliumEndpointCRDName)
	c.MasqueradeInterfaces = vp.GetStringSlice(MasqueradeInterfaces)
	c.EgressMasqueradeInterfaces = strings.Join(c.MasqueradeInterfaces, ",")
	c.BPFSocketLBHostnsOnly = vp.GetBool(BPFSocketLBHostnsOnly)
	c.EnableSocketLB = vp.GetBool(EnableSocketLB)
	c.EnableSocketLBTracing = vp.GetBool(EnableSocketLBTracing)
	c.EnableBPFTProxy = vp.GetBool(EnableBPFTProxy)
	c.EnableXTSocketFallback = vp.GetBool(EnableXTSocketFallbackName)
	c.EnableAutoDirectRouting = vp.GetBool(EnableAutoDirectRoutingName)
	c.DirectRoutingSkipUnreachable = vp.GetBool(DirectRoutingSkipUnreachableName)
	c.EnableEndpointRoutes = vp.GetBool(EnableEndpointRoutes)
	c.EnableHealthChecking = vp.GetBool(EnableHealthChecking)
	c.EnableEndpointHealthChecking = vp.GetBool(EnableEndpointHealthChecking)
	c.EnableHealthCheckNodePort = vp.GetBool(EnableHealthCheckNodePort)
	c.EnableHealthCheckLoadBalancerIP = vp.GetBool(EnableHealthCheckLoadBalancerIP)
	c.EnableLocalNodeRoute = vp.GetBool(EnableLocalNodeRoute)
	c.EnablePolicy = strings.ToLower(vp.GetString(EnablePolicy))
	c.EnableExternalIPs = vp.GetBool(EnableExternalIPs)
	c.EnableL7Proxy = vp.GetBool(EnableL7Proxy)
	c.EnableTracing = vp.GetBool(EnableTracing)
	c.EnableIPIPTermination = vp.GetBool(EnableIPIPTermination)
	c.EnableUnreachableRoutes = vp.GetBool(EnableUnreachableRoutes)
	c.EnableNodePort = vp.GetBool(EnableNodePort)
	c.EnableSVCSourceRangeCheck = vp.GetBool(EnableSVCSourceRangeCheck)
	c.EnableHostPort = vp.GetBool(EnableHostPort)
	c.EnableHostLegacyRouting = vp.GetBool(EnableHostLegacyRouting)
	c.MaglevTableSize = vp.GetInt(MaglevTableSize)
	c.MaglevHashSeed = vp.GetString(MaglevHashSeed)
	c.NodePortBindProtection = vp.GetBool(NodePortBindProtection)
	c.EnableAutoProtectNodePortRange = vp.GetBool(EnableAutoProtectNodePortRange)
	c.KubeProxyReplacement = vp.GetString(KubeProxyReplacement)
	c.EnableSessionAffinity = vp.GetBool(EnableSessionAffinity)
	c.EnableRecorder = vp.GetBool(EnableRecorder)
	c.EnableMKE = vp.GetBool(EnableMKE)
	c.CgroupPathMKE = vp.GetString(CgroupPathMKE)
	c.EnableHostFirewall = vp.GetBool(EnableHostFirewall)
	c.EnableLocalRedirectPolicy = vp.GetBool(EnableLocalRedirectPolicy)
	c.EncryptInterface = vp.GetStringSlice(EncryptInterface)
	c.EncryptNode = vp.GetBool(EncryptNode)
	c.IdentityChangeGracePeriod = vp.GetDuration(IdentityChangeGracePeriod)
	c.IdentityRestoreGracePeriod = vp.GetDuration(IdentityRestoreGracePeriod)
	c.IPAM = vp.GetString(IPAM)
	c.IPAMDefaultIPPool = vp.GetString(IPAMDefaultIPPool)
	c.IPv4Range = vp.GetString(IPv4Range)
	c.IPv4NodeAddr = vp.GetString(IPv4NodeAddr)
	c.IPv4ServiceRange = vp.GetString(IPv4ServiceRange)
	c.IPv6ClusterAllocCIDR = vp.GetString(IPv6ClusterAllocCIDRName)
	c.IPv6NodeAddr = vp.GetString(IPv6NodeAddr)
	c.IPv6Range = vp.GetString(IPv6Range)
	c.IPv6ServiceRange = vp.GetString(IPv6ServiceRange)
	c.JoinCluster = vp.GetBool(JoinClusterName)
	c.K8sRequireIPv4PodCIDR = vp.GetBool(K8sRequireIPv4PodCIDRName)
	c.K8sRequireIPv6PodCIDR = vp.GetBool(K8sRequireIPv6PodCIDRName)
	c.K8sServiceCacheSize = uint(vp.GetInt(K8sServiceCacheSize))
	c.K8sSyncTimeout = vp.GetDuration(K8sSyncTimeoutName)
	c.AllocatorListTimeout = vp.GetDuration(AllocatorListTimeoutName)
	c.K8sWatcherEndpointSelector = vp.GetString(K8sWatcherEndpointSelector)
	c.KeepConfig = vp.GetBool(KeepConfig)
	c.KVStore = vp.GetString(KVStore)
	c.KVstoreLeaseTTL = vp.GetDuration(KVstoreLeaseTTL)
	c.KVstoreKeepAliveInterval = c.KVstoreLeaseTTL / defaults.KVstoreKeepAliveIntervalFactor
	c.KVstorePeriodicSync = vp.GetDuration(KVstorePeriodicSync)
	c.KVstoreConnectivityTimeout = vp.GetDuration(KVstoreConnectivityTimeout)
	c.KVstoreMaxConsecutiveQuorumErrors = vp.GetUint(KVstoreMaxConsecutiveQuorumErrorsName)
	c.LabelPrefixFile = vp.GetString(LabelPrefixFile)
	c.Labels = vp.GetStringSlice(Labels)
	c.LibDir = vp.GetString(LibDir)
	c.LogDriver = vp.GetStringSlice(LogDriver)
	c.LogSystemLoadConfig = vp.GetBool(LogSystemLoadConfigName)
	c.Logstash = vp.GetBool(Logstash)
	c.LoopbackIPv4 = vp.GetString(LoopbackIPv4)
	c.LocalRouterIPv4 = vp.GetString(LocalRouterIPv4)
	c.LocalRouterIPv6 = vp.GetString(LocalRouterIPv6)
	c.EnableBPFClockProbe = vp.GetBool(EnableBPFClockProbe)
	c.EnableIPMasqAgent = vp.GetBool(EnableIPMasqAgent)
	c.EnableIPv4EgressGateway = vp.GetBool(EnableIPv4EgressGateway)
	c.EnableEnvoyConfig = vp.GetBool(EnableEnvoyConfig)
	c.IPMasqAgentConfigPath = vp.GetString(IPMasqAgentConfigPath)
	c.InstallIptRules = vp.GetBool(InstallIptRules)
	c.IPSecKeyFile = vp.GetString(IPSecKeyFileName)
	c.IPsecKeyRotationDuration = vp.GetDuration(IPsecKeyRotationDuration)
	c.EnableIPsecKeyWatcher = vp.GetBool(EnableIPsecKeyWatcher)
	c.EnableIPSecXfrmStateCaching = vp.GetBool(EnableIPSecXfrmStateCaching)
	c.MonitorAggregation = vp.GetString(MonitorAggregationName)
	c.MonitorAggregationInterval = vp.GetDuration(MonitorAggregationInterval)
	c.MTU = vp.GetInt(MTUName)
	c.PreAllocateMaps = vp.GetBool(PreAllocateMapsName)
	c.ProcFs = vp.GetString(ProcFs)
	c.RestoreState = vp.GetBool(Restore)
	c.RouteMetric = vp.GetInt(RouteMetric)
	c.RunDir = vp.GetString(StateDir)
	c.ExternalEnvoyProxy = vp.GetBool(ExternalEnvoyProxy)
	c.SocketPath = vp.GetString(SocketPath)
	c.TracePayloadlen = vp.GetInt(TracePayloadlen)
	c.Version = vp.GetString(Version)
	c.PolicyTriggerInterval = vp.GetDuration(PolicyTriggerInterval)
	c.CTMapEntriesTimeoutTCP = vp.GetDuration(CTMapEntriesTimeoutTCPName)
	c.CTMapEntriesTimeoutAny = vp.GetDuration(CTMapEntriesTimeoutAnyName)
	c.CTMapEntriesTimeoutSVCTCP = vp.GetDuration(CTMapEntriesTimeoutSVCTCPName)
	c.CTMapEntriesTimeoutSVCTCPGrace = vp.GetDuration(CTMapEntriesTimeoutSVCTCPGraceName)
	c.CTMapEntriesTimeoutSVCAny = vp.GetDuration(CTMapEntriesTimeoutSVCAnyName)
	c.CTMapEntriesTimeoutSYN = vp.GetDuration(CTMapEntriesTimeoutSYNName)
	c.CTMapEntriesTimeoutFIN = vp.GetDuration(CTMapEntriesTimeoutFINName)
	c.PolicyAuditMode = vp.GetBool(PolicyAuditModeArg)
	c.PolicyAccounting = vp.GetBool(PolicyAccountingArg)
	c.EnableIPv4FragmentsTracking = vp.GetBool(EnableIPv4FragmentsTrackingName)
	c.FragmentsMapEntries = vp.GetInt(FragmentsMapEntriesName)
	c.CRDWaitTimeout = vp.GetDuration(CRDWaitTimeout)
	c.LoadBalancerDSRDispatch = vp.GetString(LoadBalancerDSRDispatch)
	c.LoadBalancerDSRL4Xlate = vp.GetString(LoadBalancerDSRL4Xlate)
	c.LoadBalancerRSSv4CIDR = vp.GetString(LoadBalancerRSSv4CIDR)
	c.LoadBalancerRSSv6CIDR = vp.GetString(LoadBalancerRSSv6CIDR)
	c.LoadBalancerExternalControlPlane = vp.GetBool(LoadBalancerExternalControlPlane)
	c.InstallNoConntrackIptRules = vp.GetBool(InstallNoConntrackIptRules)
	c.ContainerIPLocalReservedPorts = vp.GetString(ContainerIPLocalReservedPorts)
	c.EnableCustomCalls = vp.GetBool(EnableCustomCallsName)
	c.BGPAnnounceLBIP = vp.GetBool(BGPAnnounceLBIP)
	c.BGPAnnouncePodCIDR = vp.GetBool(BGPAnnouncePodCIDR)
	c.BGPConfigPath = vp.GetString(BGPConfigPath)
	c.BGPSecretsNamespace = vp.GetString(BGPSecretsNamespace)
	c.ExternalClusterIP = vp.GetBool(ExternalClusterIPName)
	c.EnableNat46X64Gateway = vp.GetBool(EnableNat46X64Gateway)
	c.EnableHighScaleIPcache = vp.GetBool(EnableHighScaleIPcache)
	c.EnableIPv4Masquerade = vp.GetBool(EnableIPv4Masquerade) && c.EnableIPv4
	c.EnableIPv6Masquerade = vp.GetBool(EnableIPv6Masquerade) && c.EnableIPv6
	c.EnableBPFMasquerade = vp.GetBool(EnableBPFMasquerade)
	c.EnableMasqueradeRouteSource = vp.GetBool(EnableMasqueradeRouteSource)
	c.EnablePMTUDiscovery = vp.GetBool(EnablePMTUDiscovery)
	c.IPv6NAT46x64CIDR = defaults.IPv6NAT46x64CIDR
	c.IPAMCiliumNodeUpdateRate = vp.GetDuration(IPAMCiliumNodeUpdateRate)
	c.BPFEventsDropEnabled = vp.GetBool(BPFEventsDropEnabled)
	c.BPFEventsPolicyVerdictEnabled = vp.GetBool(BPFEventsPolicyVerdictEnabled)
	c.BPFEventsTraceEnabled = vp.GetBool(BPFEventsTraceEnabled)
	c.EnableIPSecEncryptedOverlay = vp.GetBool(EnableIPSecEncryptedOverlay)

	c.ServiceNoBackendResponse = vp.GetString(ServiceNoBackendResponse)
	switch c.ServiceNoBackendResponse {
	case ServiceNoBackendResponseReject, ServiceNoBackendResponseDrop:
	case "":
		c.ServiceNoBackendResponse = defaults.ServiceNoBackendResponse
	default:
		log.Fatalf("Invalid value for --%s: %s (must be 'reject' or 'drop')", ServiceNoBackendResponse, c.ServiceNoBackendResponse)
	}

	c.populateLoadBalancerSettings(vp)
	c.EnableRuntimeDeviceDetection = vp.GetBool(EnableRuntimeDeviceDetection)
	c.EgressMultiHomeIPRuleCompat = vp.GetBool(EgressMultiHomeIPRuleCompat)

	vlanBPFBypassIDs := vp.GetStringSlice(VLANBPFBypass)
	c.VLANBPFBypass = make([]int, 0, len(vlanBPFBypassIDs))
	for _, vlanIDStr := range vlanBPFBypassIDs {
		vlanID, err := strconv.Atoi(vlanIDStr)
		if err != nil {
			log.WithError(err).Fatalf("Cannot parse vlan ID integer from --%s option", VLANBPFBypass)
		}
		c.VLANBPFBypass = append(c.VLANBPFBypass, vlanID)
	}

	c.DisableExternalIPMitigation = vp.GetBool(DisableExternalIPMitigation)

	tcFilterPrio := vp.GetUint32(TCFilterPriority)
	if tcFilterPrio > math.MaxUint16 {
		log.Fatalf("%s cannot be higher than %d", TCFilterPriority, math.MaxUint16)
	}
	c.TCFilterPriority = uint16(tcFilterPrio)

	c.RoutingMode = vp.GetString(RoutingMode)

	if vp.IsSet(AddressScopeMax) {
		c.AddressScopeMax, err = ip.ParseScope(vp.GetString(AddressScopeMax))
		if err != nil {
			log.WithError(err).Fatalf("Cannot parse scope integer from --%s option", AddressScopeMax)
		}
	} else {
		c.AddressScopeMax = defaults.AddressScopeMax
	}

	if c.EnableNat46X64Gateway {
		if !c.EnableIPv4 || !c.EnableIPv6 {
			log.Fatalf("--%s requires both --%s and --%s enabled",
				EnableNat46X64Gateway, EnableIPv4Name, EnableIPv6Name)
		}
	}

	encryptionStrictModeEnabled := vp.GetBool(EnableEncryptionStrictMode)
	if encryptionStrictModeEnabled {
		if c.EnableIPv6 {
			log.Warnf("WireGuard encryption strict mode only support IPv4. IPv6 traffic is not protected and can be leaked.")
		}

		strictCIDR := vp.GetString(EncryptionStrictModeCIDR)
		c.EncryptionStrictModeCIDR, err = netip.ParsePrefix(strictCIDR)
		if err != nil {
			log.WithError(err).Fatalf("Cannot parse CIDR %s from --%s option", strictCIDR, EncryptionStrictModeCIDR)
		}

		if !c.EncryptionStrictModeCIDR.Addr().Is4() {
			log.Fatalf("%s must be an IPv4 CIDR", EncryptionStrictModeCIDR)
		}

		c.EncryptionStrictModeAllowRemoteNodeIdentities = vp.GetBool(EncryptionStrictModeAllowRemoteNodeIdentities)
		c.EnableEncryptionStrictMode = encryptionStrictModeEnabled
	}

	ipv4NativeRoutingCIDR := vp.GetString(IPv4NativeRoutingCIDR)

	if ipv4NativeRoutingCIDR != "" {
		c.IPv4NativeRoutingCIDR, err = cidr.ParseCIDR(ipv4NativeRoutingCIDR)
		if err != nil {
			log.WithError(err).Fatalf("Unable to parse CIDR '%s'", ipv4NativeRoutingCIDR)
		}

		if len(c.IPv4NativeRoutingCIDR.IP) != net.IPv4len {
			log.Fatalf("%s must be an IPv4 CIDR", IPv4NativeRoutingCIDR)
		}
	}

	if c.EnableIPv4 && ipv4NativeRoutingCIDR == "" && c.EnableAutoDirectRouting {
		log.Warnf("If %s is enabled, then you are recommended to also configure %s. If %s is not configured, this may lead to pod to pod traffic being masqueraded, "+
			"which can cause problems with performance, observability and policy", EnableAutoDirectRoutingName, IPv4NativeRoutingCIDR, IPv4NativeRoutingCIDR)
	}

	ipv6NativeRoutingCIDR := vp.GetString(IPv6NativeRoutingCIDR)

	if ipv6NativeRoutingCIDR != "" {
		c.IPv6NativeRoutingCIDR, err = cidr.ParseCIDR(ipv6NativeRoutingCIDR)
		if err != nil {
			log.WithError(err).Fatalf("Unable to parse CIDR '%s'", ipv6NativeRoutingCIDR)
		}

		if len(c.IPv6NativeRoutingCIDR.IP) != net.IPv6len {
			log.Fatalf("%s must be an IPv6 CIDR", IPv6NativeRoutingCIDR)
		}
	}

	if c.EnableIPv6 && ipv6NativeRoutingCIDR == "" && c.EnableAutoDirectRouting {
		log.Warnf("If %s is enabled, then you are recommended to also configure %s. If %s is not configured, this may lead to pod to pod traffic being masqueraded, "+
			"which can cause problems with performance, observability and policy", EnableAutoDirectRoutingName, IPv6NativeRoutingCIDR, IPv6NativeRoutingCIDR)
	}

	if c.DirectRoutingSkipUnreachable && !c.EnableAutoDirectRouting {
		log.Fatalf("Flag %s cannot be enabled when %s is not enabled. As if %s is then enabled, it may lead to unexpected behaviour causing network connectivity issues.", DirectRoutingSkipUnreachableName, EnableAutoDirectRoutingName, EnableAutoDirectRoutingName)
	}

	if err := c.calculateBPFMapSizes(vp); err != nil {
		log.Fatal(err)
	}

	c.ClockSource = ClockSourceKtime
	c.EnableIdentityMark = vp.GetBool(EnableIdentityMark)

	// toFQDNs options
	c.DNSMaxIPsPerRestoredRule = vp.GetInt(DNSMaxIPsPerRestoredRule)
	c.DNSPolicyUnloadOnShutdown = vp.GetBool(DNSPolicyUnloadOnShutdown)
	c.FQDNRegexCompileLRUSize = vp.GetInt(FQDNRegexCompileLRUSize)
	c.ToFQDNsMaxIPsPerHost = vp.GetInt(ToFQDNsMaxIPsPerHost)
	if maxZombies := vp.GetInt(ToFQDNsMaxDeferredConnectionDeletes); maxZombies >= 0 {
		c.ToFQDNsMaxDeferredConnectionDeletes = vp.GetInt(ToFQDNsMaxDeferredConnectionDeletes)
	} else {
		log.Fatalf("%s must be positive, or 0 to disable deferred connection deletion",
			ToFQDNsMaxDeferredConnectionDeletes)
	}
	switch {
	case vp.IsSet(ToFQDNsMinTTL): // set by user
		c.ToFQDNsMinTTL = vp.GetInt(ToFQDNsMinTTL)
	default:
		c.ToFQDNsMinTTL = defaults.ToFQDNsMinTTL
	}
	c.ToFQDNsProxyPort = vp.GetInt(ToFQDNsProxyPort)
	c.ToFQDNsPreCache = vp.GetString(ToFQDNsPreCache)
	c.ToFQDNsEnableDNSCompression = vp.GetBool(ToFQDNsEnableDNSCompression)
	c.ToFQDNsIdleConnectionGracePeriod = vp.GetDuration(ToFQDNsIdleConnectionGracePeriod)
	c.FQDNProxyResponseMaxDelay = vp.GetDuration(FQDNProxyResponseMaxDelay)
	c.DNSProxyConcurrencyLimit = vp.GetInt(DNSProxyConcurrencyLimit)
	c.DNSProxyConcurrencyProcessingGracePeriod = vp.GetDuration(DNSProxyConcurrencyProcessingGracePeriod)
	c.DNSProxyEnableTransparentMode = vp.GetBool(DNSProxyEnableTransparentMode)
	c.DNSProxyInsecureSkipTransparentModeCheck = vp.GetBool(DNSProxyInsecureSkipTransparentModeCheck)
	c.DNSProxyLockCount = vp.GetInt(DNSProxyLockCount)
	c.DNSProxyLockTimeout = vp.GetDuration(DNSProxyLockTimeout)
	c.DNSProxySocketLingerTimeout = vp.GetInt(DNSProxySocketLingerTimeout)
	c.FQDNRejectResponse = vp.GetString(FQDNRejectResponseCode)

	// Convert IP strings into net.IPNet types
	subnets, invalid := ip.ParseCIDRs(vp.GetStringSlice(IPv4PodSubnets))
	if len(invalid) > 0 {
		log.WithFields(
			logrus.Fields{
				"Subnets": invalid,
			}).Warning("IPv4PodSubnets parameter can not be parsed.")
	}
	c.IPv4PodSubnets = subnets

	subnets, invalid = ip.ParseCIDRs(vp.GetStringSlice(IPv6PodSubnets))
	if len(invalid) > 0 {
		log.WithFields(
			logrus.Fields{
				"Subnets": invalid,
			}).Warning("IPv6PodSubnets parameter can not be parsed.")
	}
	c.IPv6PodSubnets = subnets

	c.XDPMode = XDPModeLinkNone

	err = c.populateNodePortRange(vp)
	if err != nil {
		log.WithError(err).Fatal("Failed to populate NodePortRange")
	}

	monitorAggregationFlags := vp.GetStringSlice(MonitorAggregationFlags)
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
	if m := command.GetStringMapString(vp, FixedIdentityMapping); err != nil {
		log.Fatalf("unable to parse %s: %s", FixedIdentityMapping, err)
	} else if len(m) != 0 {
		c.FixedIdentityMapping = m
	}

	if m := command.GetStringMapString(vp, FixedZoneMapping); err != nil {
		log.Fatalf("unable to parse %s: %s", FixedZoneMapping, err)
	} else if len(m) != 0 {
		forward := make(map[string]uint8, len(m))
		reverse := make(map[uint8]string, len(m))
		for k, v := range m {
			bigN, _ := strconv.Atoi(v)
			n := uint8(bigN)
			if oldKey, ok := reverse[n]; ok && oldKey != k {
				log.Fatalf("duplicate numeric ID entry for %s: %q and %q map to the same value %d", FixedZoneMapping, oldKey, k, n)
			}
			if oldN, ok := forward[k]; ok && oldN != n {
				log.Fatalf("duplicate zone name entry for %s: %d and %d map to different values %s", FixedZoneMapping, oldN, n, k)
			}
			forward[k] = n
			reverse[n] = k
		}
		c.FixedZoneMapping = forward
		c.ReverseFixedZoneMapping = reverse
	}

	c.ConntrackGCInterval = vp.GetDuration(ConntrackGCInterval)
	c.ConntrackGCMaxInterval = vp.GetDuration(ConntrackGCMaxInterval)

	if m, err := command.GetStringMapStringE(vp, KVStoreOpt); err != nil {
		log.Fatalf("unable to parse %s: %s", KVStoreOpt, err)
	} else {
		c.KVStoreOpt = m
	}

	if m, err := command.GetStringMapStringE(vp, LogOpt); err != nil {
		log.Fatalf("unable to parse %s: %s", LogOpt, err)
	} else {
		c.LogOpt = m
	}

	bpfEventsDefaultRateLimit := vp.GetUint32(BPFEventsDefaultRateLimit)
	bpfEventsDefaultBurstLimit := vp.GetUint32(BPFEventsDefaultBurstLimit)
	switch {
	case bpfEventsDefaultRateLimit > 0 && bpfEventsDefaultBurstLimit == 0:
		log.Fatalf("invalid BPF events default config: burst limit must also be specified when rate limit is provided")
	case bpfEventsDefaultRateLimit == 0 && bpfEventsDefaultBurstLimit > 0:
		log.Fatalf("invalid BPF events default config: rate limit must also be specified when burst limit is provided")
	default:
		c.BPFEventsDefaultRateLimit = vp.GetUint32(BPFEventsDefaultRateLimit)
		c.BPFEventsDefaultBurstLimit = vp.GetUint32(BPFEventsDefaultBurstLimit)
	}

	c.bpfMapEventConfigs = make(BPFEventBufferConfigs)
	parseBPFMapEventConfigs(c.bpfMapEventConfigs, defaults.BPFEventBufferConfigs)
	if m, err := command.GetStringMapStringE(vp, BPFMapEventBuffers); err != nil {
		log.Fatalf("unable to parse %s: %s", BPFMapEventBuffers, err)
	} else {
		parseBPFMapEventConfigs(c.bpfMapEventConfigs, m)
	}

	c.NodeEncryptionOptOutLabelsString = vp.GetString(NodeEncryptionOptOutLabels)
	if sel, err := k8sLabels.Parse(c.NodeEncryptionOptOutLabelsString); err != nil {
		log.Fatalf("unable to parse label selector %s: %s", NodeEncryptionOptOutLabels, err)
	} else {
		c.NodeEncryptionOptOutLabels = sel
	}

	if err := c.parseExcludedLocalAddresses(vp.GetStringSlice(ExcludeLocalAddress)); err != nil {
		log.WithError(err).Fatalf("Unable to parse excluded local addresses")
	}

	// Ensure CiliumEndpointSlice is enabled only if CiliumEndpointCRD is enabled too.
	c.EnableCiliumEndpointSlice = vp.GetBool(EnableCiliumEndpointSlice)
	if c.EnableCiliumEndpointSlice && c.DisableCiliumEndpointCRD {
		log.Fatalf("Running Cilium with %s=%t requires %s set to false to enable CiliumEndpoint CRDs.",
			EnableCiliumEndpointSlice, c.EnableCiliumEndpointSlice, DisableCiliumEndpointCRDName)
	}

	c.IdentityAllocationMode = vp.GetString(IdentityAllocationMode)
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
	}

	switch c.IPAM {
	case ipamOption.IPAMKubernetes, ipamOption.IPAMClusterPool:
		if c.EnableIPv4 {
			c.K8sRequireIPv4PodCIDR = true
		}

		if c.EnableIPv6 {
			c.K8sRequireIPv6PodCIDR = true
		}
	}
	if m, err := command.GetStringMapStringE(vp, IPAMMultiPoolPreAllocation); err != nil {
		log.Fatalf("unable to parse %s: %s", IPAMMultiPoolPreAllocation, err)
	} else {
		c.IPAMMultiPoolPreAllocation = m
	}
	if len(c.IPAMMultiPoolPreAllocation) == 0 {
		// Default to the same value as IPAMDefaultIPPool
		c.IPAMMultiPoolPreAllocation = map[string]string{c.IPAMDefaultIPPool: "8"}
	}
	c.KubeProxyReplacementHealthzBindAddr = vp.GetString(KubeProxyReplacementHealthzBindAddr)

	// Hubble options.
	c.EnableHubble = vp.GetBool(EnableHubble)
	c.EnableHubbleOpenMetrics = vp.GetBool(EnableHubbleOpenMetrics)
	c.HubbleSocketPath = vp.GetString(HubbleSocketPath)
	c.HubbleListenAddress = vp.GetString(HubbleListenAddress)
	c.HubblePreferIpv6 = vp.GetBool(HubblePreferIpv6)
	c.HubbleTLSDisabled = vp.GetBool(HubbleTLSDisabled)
	c.HubbleTLSCertFile = vp.GetString(HubbleTLSCertFile)
	c.HubbleTLSKeyFile = vp.GetString(HubbleTLSKeyFile)
	c.HubbleTLSClientCAFiles = vp.GetStringSlice(HubbleTLSClientCAFiles)
	c.HubbleEventBufferCapacity = vp.GetInt(HubbleEventBufferCapacity)
	c.HubbleEventQueueSize = vp.GetInt(HubbleEventQueueSize)
	if c.HubbleEventQueueSize == 0 {
		c.HubbleEventQueueSize = getDefaultMonitorQueueSize(runtime.NumCPU())
	}
	c.HubbleMetricsServer = vp.GetString(HubbleMetricsServer)
	c.HubbleMetricsServerTLSEnabled = vp.GetBool(HubbleMetricsTLSEnabled)
	c.HubbleMetricsServerTLSCertFile = vp.GetString(HubbleMetricsTLSCertFile)
	c.HubbleMetricsServerTLSKeyFile = vp.GetString(HubbleMetricsTLSKeyFile)
	c.HubbleMetricsServerTLSClientCAFiles = vp.GetStringSlice(HubbleMetricsTLSClientCAFiles)
	c.HubbleMetrics = vp.GetStringSlice(HubbleMetrics)

	c.HubbleExportFilePath = vp.GetString(HubbleExportFilePath)
	c.HubbleExportFileMaxSizeMB = vp.GetInt(HubbleExportFileMaxSizeMB)
	c.HubbleExportFileMaxBackups = vp.GetInt(HubbleExportFileMaxBackups)
	c.HubbleExportFileCompress = vp.GetBool(HubbleExportFileCompress)

	for _, enc := range vp.GetStringSlice(HubbleExportAllowlist) {
		dec := json.NewDecoder(strings.NewReader(enc))
		var result flowpb.FlowFilter
		if err := dec.Decode(&result); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			log.Fatalf("failed to decode hubble-export-allowlist '%v': %s", enc, err)
		}
		c.HubbleExportAllowlist = append(c.HubbleExportAllowlist, &result)
	}

	for _, enc := range vp.GetStringSlice(HubbleExportDenylist) {
		dec := json.NewDecoder(strings.NewReader(enc))
		var result flowpb.FlowFilter
		if err := dec.Decode(&result); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			log.Fatalf("failed to decode hubble-export-denylist '%v': %s", enc, err)
		}
		c.HubbleExportDenylist = append(c.HubbleExportDenylist, &result)
	}

	if fm := vp.GetStringSlice(HubbleExportFieldmask); len(fm) > 0 {
		_, err := fieldmaskpb.New(&flowpb.Flow{}, fm...)
		if err != nil {
			log.Fatalf("hubble-export-fieldmask contains invalid fieldmask '%v': %s", fm, err)
		}
		c.HubbleExportFieldmask = vp.GetStringSlice(HubbleExportFieldmask)
	}

	c.HubbleFlowlogsConfigFilePath = vp.GetString(HubbleFlowlogsConfigFilePath)

	c.EnableHubbleRecorderAPI = vp.GetBool(EnableHubbleRecorderAPI)
	c.HubbleRecorderStoragePath = vp.GetString(HubbleRecorderStoragePath)
	c.HubbleRecorderSinkQueueSize = vp.GetInt(HubbleRecorderSinkQueueSize)
	c.HubbleSkipUnknownCGroupIDs = vp.GetBool(HubbleSkipUnknownCGroupIDs)
	c.HubbleMonitorEvents = vp.GetStringSlice(HubbleMonitorEvents)
	c.HubbleRedactEnabled = vp.GetBool(HubbleRedactEnabled)
	c.HubbleRedactHttpURLQuery = vp.GetBool(HubbleRedactHttpURLQuery)
	c.HubbleRedactHttpUserInfo = vp.GetBool(HubbleRedactHttpUserInfo)
	c.HubbleRedactKafkaApiKey = vp.GetBool(HubbleRedactKafkaApiKey)
	c.HubbleRedactHttpHeadersAllow = vp.GetStringSlice(HubbleRedactHttpHeadersAllow)
	c.HubbleRedactHttpHeadersDeny = vp.GetStringSlice(HubbleRedactHttpHeadersDeny)
	c.HubbleDropEvents = vp.GetBool(HubbleDropEvents)
	c.HubbleDropEventsInterval = vp.GetDuration(HubbleDropEventsInterval)
	c.HubbleDropEventsReasons = vp.GetStringSlice(HubbleDropEventsReasons)

	// Hidden options
	c.CompilerFlags = vp.GetStringSlice(CompilerFlags)
	c.ConfigFile = vp.GetString(ConfigFile)
	c.HTTP403Message = vp.GetString(HTTP403Message)
	c.K8sNamespace = vp.GetString(K8sNamespaceName)
	c.AgentNotReadyNodeTaintKey = vp.GetString(AgentNotReadyNodeTaintKeyName)
	c.MaxControllerInterval = vp.GetInt(MaxCtrlIntervalName)
	c.PolicyQueueSize = sanitizeIntParam(vp, PolicyQueueSize, defaults.PolicyQueueSize)
	c.EndpointQueueSize = sanitizeIntParam(vp, EndpointQueueSize, defaults.EndpointQueueSize)
	c.EnableICMPRules = vp.GetBool(EnableICMPRules)
	c.UseCiliumInternalIPForIPsec = vp.GetBool(UseCiliumInternalIPForIPsec)
	c.BypassIPAvailabilityUponRestore = vp.GetBool(BypassIPAvailabilityUponRestore)
	c.EnableK8sTerminatingEndpoint = vp.GetBool(EnableK8sTerminatingEndpoint)

	// VTEP integration enable option
	c.EnableVTEP = vp.GetBool(EnableVTEP)

	// Enable BGP control plane features
	c.EnableBGPControlPlane = vp.GetBool(EnableBGPControlPlane)

	// To support K8s NetworkPolicy
	c.EnableK8sNetworkPolicy = vp.GetBool(EnableK8sNetworkPolicy)
	c.PolicyCIDRMatchMode = vp.GetStringSlice(PolicyCIDRMatchMode)
	c.EnableNodeSelectorLabels = vp.GetBool(EnableNodeSelectorLabels)
	c.NodeLabels = vp.GetStringSlice(NodeLabels)

	// Parse node label patterns
	nodeLabelPatterns := vp.GetStringSlice(ExcludeNodeLabelPatterns)
	for _, pattern := range nodeLabelPatterns {
		r, err := regexp.Compile(pattern)
		if err != nil {
			log.WithError(err).Errorf("Unable to compile exclude node label regex pattern %s", pattern)
			continue
		}
		c.ExcludeNodeLabelPatterns = append(c.ExcludeNodeLabelPatterns, r)
	}

	if c.KVStore != "" {
		c.IdentityRestoreGracePeriod = defaults.IdentityRestoreGracePeriodKvstore
	}
}

func (c *DaemonConfig) populateLoadBalancerSettings(vp *viper.Viper) {
	c.NodePortAcceleration = vp.GetString(LoadBalancerAcceleration)
	c.NodePortMode = vp.GetString(LoadBalancerMode)
	c.NodePortAlg = vp.GetString(LoadBalancerAlg)
	// If old settings were explicitly set by the user, then have them
	// override the new ones in order to not break existing setups.
	if vp.IsSet(NodePortAcceleration) {
		prior := c.NodePortAcceleration
		c.NodePortAcceleration = vp.GetString(NodePortAcceleration)
		if vp.IsSet(LoadBalancerAcceleration) && prior != c.NodePortAcceleration {
			log.Fatalf("Both --%s and --%s were set. Only use --%s instead.",
				LoadBalancerAcceleration, NodePortAcceleration, LoadBalancerAcceleration)
		}
	}
	if vp.IsSet(NodePortMode) {
		prior := c.NodePortMode
		c.NodePortMode = vp.GetString(NodePortMode)
		if vp.IsSet(LoadBalancerMode) && prior != c.NodePortMode {
			log.Fatalf("Both --%s and --%s were set. Only use --%s instead.",
				LoadBalancerMode, NodePortMode, LoadBalancerMode)
		}
	}
	if vp.IsSet(NodePortAlg) {
		prior := c.NodePortAlg
		c.NodePortAlg = vp.GetString(NodePortAlg)
		if vp.IsSet(LoadBalancerAlg) && prior != c.NodePortAlg {
			log.Fatalf("Both --%s and --%s were set. Only use --%s instead.",
				LoadBalancerAlg, NodePortAlg, LoadBalancerAlg)
		}
	}
}

func (c *DaemonConfig) populateNodePortRange(vp *viper.Viper) error {
	nodePortRange := vp.GetStringSlice(NodePortRange)
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
			return fmt.Errorf("Unable to parse min port value for NodePort range: %w", err)
		}
		c.NodePortMax, err = strconv.Atoi(nodePortRange[1])
		if err != nil {
			return fmt.Errorf("Unable to parse max port value for NodePort range: %w", err)
		}
		if c.NodePortMax <= c.NodePortMin {
			return errors.New("NodePort range min port must be smaller than max port")
		}
	case 0:
		if vp.IsSet(NodePortRange) {
			log.Warning("NodePort range was set but is empty.")
		}
	default:
		return fmt.Errorf("Unable to parse min/max port value for NodePort range: %s", NodePortRange)
	}

	return nil
}

func (c *DaemonConfig) checkMapSizeLimits() error {
	if c.AuthMapEntries < AuthMapEntriesMin {
		return fmt.Errorf("specified AuthMap max entries %d must exceed minimum %d", c.AuthMapEntries, AuthMapEntriesMin)
	}
	if c.AuthMapEntries > AuthMapEntriesMax {
		return fmt.Errorf("specified AuthMap max entries %d must not exceed maximum %d", c.AuthMapEntries, AuthMapEntriesMax)
	}

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
		log.Warnf("specified PolicyMap max entries %d must not exceed maximum %d, lowering it to the maximum value",
			c.PolicyMapEntries, PolicyMapMax)
		c.PolicyMapEntries = PolicyMapMax
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
	if c.IPv4NativeRoutingCIDR != nil {
		return nil
	}
	if !c.EnableIPv4 || !c.EnableIPv4Masquerade {
		return nil
	}
	if c.EnableIPMasqAgent {
		return nil
	}
	if c.TunnelingEnabled() {
		return nil
	}
	if c.IPAMMode() == ipamOption.IPAMENI || c.IPAMMode() == ipamOption.IPAMAlibabaCloud {
		return nil
	}

	return fmt.Errorf(
		"native routing cidr must be configured with option --%s "+
			"in combination with --%s=true --%s=true --%s=false --%s=%s --%s=%s",
		IPv4NativeRoutingCIDR,
		EnableIPv4Name, EnableIPv4Masquerade,
		EnableIPMasqAgent,
		RoutingMode, RoutingModeNative,
		IPAM, c.IPAMMode())
}

func (c *DaemonConfig) checkIPv6NativeRoutingCIDR() error {
	if c.IPv6NativeRoutingCIDR != nil {
		return nil
	}
	if !c.EnableIPv6 || !c.EnableIPv6Masquerade {
		return nil
	}
	if c.EnableIPMasqAgent {
		return nil
	}
	if c.TunnelingEnabled() {
		return nil
	}
	return fmt.Errorf(
		"native routing cidr must be configured with option --%s "+
			"in combination with --%s=true --%s=true --%s=false --%s=%s",
		IPv6NativeRoutingCIDR,
		EnableIPv6Name, EnableIPv6Masquerade,
		EnableIPMasqAgent,
		RoutingMode, RoutingModeNative)
}

func (c *DaemonConfig) checkIPAMDelegatedPlugin() error {
	if c.IPAM == ipamOption.IPAMDelegatedPlugin {
		// When using IPAM delegated plugin, IP addresses are allocated by the CNI binary,
		// not the daemon. Therefore, features which require the daemon to allocate IPs for itself
		// must be disabled.
		if c.EnableIPv4 && c.LocalRouterIPv4 == "" {
			return fmt.Errorf("--%s must be provided when IPv4 is enabled with --%s=%s", LocalRouterIPv4, IPAM, ipamOption.IPAMDelegatedPlugin)
		}
		if c.EnableIPv6 && c.LocalRouterIPv6 == "" {
			return fmt.Errorf("--%s must be provided when IPv6 is enabled with --%s=%s", LocalRouterIPv6, IPAM, ipamOption.IPAMDelegatedPlugin)
		}
		if c.EnableEndpointHealthChecking {
			return fmt.Errorf("--%s must be disabled with --%s=%s", EnableEndpointHealthChecking, IPAM, ipamOption.IPAMDelegatedPlugin)
		}
		// envoy config (Ingress, Gateway API, ...) require cilium-agent to create an IP address
		// specifically for differentiating envoy traffic, which is not possible
		// with delegated IPAM.
		if c.EnableEnvoyConfig {
			return fmt.Errorf("--%s must be disabled with --%s=%s", EnableEnvoyConfig, IPAM, ipamOption.IPAMDelegatedPlugin)
		}
	}
	return nil
}

func (c *DaemonConfig) calculateBPFMapSizes(vp *viper.Viper) error {
	// BPF map size options
	// Any map size explicitly set via option will override the dynamic
	// sizing.
	c.AuthMapEntries = vp.GetInt(AuthMapEntriesName)
	c.CTMapEntriesGlobalTCP = vp.GetInt(CTMapEntriesGlobalTCPName)
	c.CTMapEntriesGlobalAny = vp.GetInt(CTMapEntriesGlobalAnyName)
	c.NATMapEntriesGlobal = vp.GetInt(NATMapEntriesGlobalName)
	c.NeighMapEntriesGlobal = vp.GetInt(NeighMapEntriesGlobalName)
	c.PolicyMapEntries = vp.GetInt(PolicyMapEntriesName)
	c.PolicyMapFullReconciliationInterval = vp.GetDuration(PolicyMapFullReconciliationIntervalName)
	c.SockRevNatEntries = vp.GetInt(SockRevNatEntriesName)
	c.LBMapEntries = vp.GetInt(LBMapEntriesName)
	c.LBServiceMapEntries = vp.GetInt(LBServiceMapMaxEntries)
	c.LBBackendMapEntries = vp.GetInt(LBBackendMapMaxEntries)
	c.LBRevNatEntries = vp.GetInt(LBRevNatMapMaxEntries)
	c.LBAffinityMapEntries = vp.GetInt(LBAffinityMapMaxEntries)
	c.LBSourceRangeMapEntries = vp.GetInt(LBSourceRangeMapMaxEntries)
	c.LBMaglevMapEntries = vp.GetInt(LBMaglevMapMaxEntries)

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
	dynamicSizeRatio := vp.GetFloat64(MapEntriesGlobalDynamicSizeRatioName)
	if 0.0 < dynamicSizeRatio && dynamicSizeRatio <= 1.0 {
		vms, err := memory.Get()
		if err != nil || vms == nil {
			log.WithError(err).Fatal("Failed to get system memory")
		}
		c.calculateDynamicBPFMapSizes(vp, vms.Total, dynamicSizeRatio)
		c.BPFMapsDynamicSizeRatio = dynamicSizeRatio
	} else if dynamicSizeRatio < 0.0 {
		return fmt.Errorf("specified dynamic map size ratio %f must be > 0.0", dynamicSizeRatio)
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

func (c *DaemonConfig) calculateDynamicBPFMapSizes(vp *viper.Viper, totalMemory uint64, dynamicSizeRatio float64) {
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
	if !vp.IsSet(CTMapEntriesGlobalTCPName) {
		c.CTMapEntriesGlobalTCP =
			getEntries(CTMapEntriesGlobalTCPDefault, LimitTableAutoGlobalTCPMin, LimitTableMax)
		log.Infof("option %s set by dynamic sizing to %v",
			CTMapEntriesGlobalTCPName, c.CTMapEntriesGlobalTCP)
	} else {
		log.Debugf("option %s set by user to %v", CTMapEntriesGlobalTCPName, c.CTMapEntriesGlobalTCP)
	}
	if !vp.IsSet(CTMapEntriesGlobalAnyName) {
		c.CTMapEntriesGlobalAny =
			getEntries(CTMapEntriesGlobalAnyDefault, LimitTableAutoGlobalAnyMin, LimitTableMax)
		log.Infof("option %s set by dynamic sizing to %v",
			CTMapEntriesGlobalAnyName, c.CTMapEntriesGlobalAny)
	} else {
		log.Debugf("option %s set by user to %v", CTMapEntriesGlobalAnyName, c.CTMapEntriesGlobalAny)
	}
	if !vp.IsSet(NATMapEntriesGlobalName) {
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
	if !vp.IsSet(NeighMapEntriesGlobalName) {
		// By default we auto-size it to the same value as the NAT map since we
		// need to keep at least as many neigh entries.
		c.NeighMapEntriesGlobal = c.NATMapEntriesGlobal
		log.Infof("option %s set by dynamic sizing to %v",
			NeighMapEntriesGlobalName, c.NeighMapEntriesGlobal)
	} else {
		log.Debugf("option %s set by user to %v", NeighMapEntriesGlobalName, c.NeighMapEntriesGlobal)
	}
	if !vp.IsSet(SockRevNatEntriesName) {
		c.SockRevNatEntries =
			getEntries(SockRevNATMapEntriesDefault, LimitTableAutoSockRevNatMin, LimitTableMax)
		log.Infof("option %s set by dynamic sizing to %v",
			SockRevNatEntriesName, c.SockRevNatEntries)
	} else {
		log.Debugf("option %s set by user to %v", NATMapEntriesGlobalName, c.NATMapEntriesGlobal)
	}
}

// Validate VTEP integration configuration
func (c *DaemonConfig) validateVTEP(vp *viper.Viper) error {
	vtepEndpoints := vp.GetStringSlice(VtepEndpoint)
	vtepCIDRs := vp.GetStringSlice(VtepCIDR)
	vtepCidrMask := vp.GetString(VtepMask)
	vtepMACs := vp.GetStringSlice(VtepMAC)

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
func (c *DaemonConfig) KubeProxyReplacementFullyEnabled() bool {
	return c.EnableHostPort &&
		c.EnableNodePort &&
		c.EnableExternalIPs &&
		c.EnableSocketLB &&
		c.EnableSessionAffinity
}

var backupFileNames []string = []string{
	"agent-runtime-config.json",
	"agent-runtime-config-1.json",
	"agent-runtime-config-2.json",
}

// StoreInFile stores the configuration in a the given directory under the file
// name 'daemon-config.json'. If this file already exists, it is renamed to
// 'daemon-config-1.json', if 'daemon-config-1.json' also exists,
// 'daemon-config-1.json' is renamed to 'daemon-config-2.json'
func (c *DaemonConfig) StoreInFile(dir string) error {
	backupFiles(dir, backupFileNames)
	f, err := os.Create(backupFileNames[0])
	if err != nil {
		return err
	}
	defer f.Close()
	e := json.NewEncoder(f)
	e.SetIndent("", " ")

	// Exclude concurrent modification of fields protected by c.ConfigPatchMutex
	// we store the file
	c.ConfigPatchMutex.RLock()
	err = e.Encode(c)
	c.shaSum = c.checksum()
	c.ConfigPatchMutex.RUnlock()

	return err
}

func (c *DaemonConfig) checksum() [32]byte {
	// take a shallow copy for summing
	sumConfig := *c
	// Ignore variable parts
	sumConfig.Opts = nil
	cBytes, err := json.Marshal(&sumConfig)
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(cBytes)
}

// ValidateUnchanged takes a context that is unused so that it can be used as a doFunc in a
// controller
func (c *DaemonConfig) ValidateUnchanged(context.Context) error {
	// Exclude concurrent modification of fields protected by c.ConfigPatchMutex
	// we store the file
	c.ConfigPatchMutex.RLock()
	sum := c.checksum()
	c.ConfigPatchMutex.RUnlock()

	if sum != c.shaSum {
		return c.diffFromFile()
	}
	return nil
}

func (c *DaemonConfig) diffFromFile() error {
	f, err := os.Open(backupFileNames[0])
	if err != nil {
		return err
	}

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	fileBytes := make([]byte, fi.Size())
	count, err := f.Read(fileBytes)
	if err != nil {
		return err
	}
	fileBytes = fileBytes[:count]

	var config DaemonConfig
	err = json.Unmarshal(fileBytes, &config)

	var diff string
	if err != nil {
		diff = fmt.Errorf("unmarshal failed %q: %w", string(fileBytes), err).Error()
	} else {
		// Ignore all unexported fields during Diff.
		// from https://github.com/google/go-cmp/issues/313#issuecomment-1315651560
		opts := cmp.FilterPath(func(p cmp.Path) bool {
			sf, ok := p.Index(-1).(cmp.StructField)
			if !ok {
				return false
			}
			r, _ := utf8.DecodeRuneInString(sf.Name())
			return !unicode.IsUpper(r)
		}, cmp.Ignore())

		diff = cmp.Diff(&config, c, opts,
			cmpopts.IgnoreTypes(&IntOptions{}),
			cmpopts.IgnoreTypes(&OptionLibrary{}))
	}
	return fmt.Errorf("Config differs:\n%s", diff)
}

func (c *DaemonConfig) BGPControlPlaneEnabled() bool {
	return c.EnableBGPControlPlane
}

func (c *DaemonConfig) IsDualStack() bool {
	return c.EnableIPv4 && c.EnableIPv6
}

// IsLocalRouterIP checks if provided IP address matches either LocalRouterIPv4
// or LocalRouterIPv6
func (c *DaemonConfig) IsLocalRouterIP(ip string) bool {
	return ip != "" && (c.LocalRouterIPv4 == ip || c.LocalRouterIPv6 == ip)
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

func sanitizeIntParam(vp *viper.Viper, paramName string, paramDefault int) int {
	intParam := vp.GetInt(paramName)
	if intParam <= 0 {
		if vp.IsSet(paramName) {
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

// validateConfigMap checks whether the flag exists and validate its value
func validateConfigMap(cmd *cobra.Command, m map[string]interface{}) error {
	flags := cmd.Flags()

	for key, value := range m {
		flag := flags.Lookup(key)
		if flag == nil {
			continue
		}

		var err error

		switch t := flag.Value.Type(); t {
		case "bool":
			_, err = cast.ToBoolE(value)
		case "duration":
			_, err = cast.ToDurationE(value)
		case "float32":
			_, err = cast.ToFloat32E(value)
		case "float64":
			_, err = cast.ToFloat64E(value)
		case "int":
			_, err = cast.ToIntE(value)
		case "int8":
			_, err = cast.ToInt8E(value)
		case "int16":
			_, err = cast.ToInt16E(value)
		case "int32":
			_, err = cast.ToInt32E(value)
		case "int64":
			_, err = cast.ToInt64E(value)
		case "map":
			// custom type, see pkg/option/map_options.go
			err = flag.Value.Set(fmt.Sprintf("%s", value))
		case "stringSlice":
			_, err = cast.ToStringSliceE(value)
		case "string":
			_, err = cast.ToStringE(value)
		case "uint":
			_, err = cast.ToUintE(value)
		case "uint8":
			_, err = cast.ToUint8E(value)
		case "uint16":
			_, err = cast.ToUint16E(value)
		case "uint32":
			_, err = cast.ToUint32E(value)
		case "uint64":
			_, err = cast.ToUint64E(value)
		default:
			log.Warnf("Unable to validate option %s value of type %s", key, t)
		}

		if err != nil {
			return fmt.Errorf("option %s: %w", key, err)
		}
	}

	return nil
}

// InitConfig reads in config file and ENV variables if set.
func InitConfig(cmd *cobra.Command, programName, configName string, vp *viper.Viper) func() {
	return func() {
		if vp.GetBool("version") {
			fmt.Printf("%s %s\n", programName, version.Version)
			os.Exit(0)
		}

		if vp.GetString(CMDRef) != "" {
			return
		}

		Config.ConfigFile = vp.GetString(ConfigFile) // enable ability to specify config file via flag
		Config.ConfigDir = vp.GetString(ConfigDir)
		vp.SetEnvPrefix("cilium")

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
				if err := validateConfigMap(cmd, m); err != nil {
					log.WithError(err).Fatal("Incorrect config-map flag value")
				}

				if err := MergeConfig(vp, m); err != nil {
					log.WithError(err).Fatal("Unable to merge configuration")
				}
			}
		}

		if Config.ConfigFile != "" {
			vp.SetConfigFile(Config.ConfigFile)
		} else {
			vp.SetConfigName(configName) // name of config file (without extension)
			vp.AddConfigPath("$HOME")    // adding home directory as first search path
		}

		// We need to check for the debug environment variable or CLI flag before
		// loading the configuration file since on configuration file read failure
		// we will emit a debug log entry.
		if vp.GetBool(DebugArg) {
			logging.SetLogLevelToDebug()
		}

		// If a config file is found, read it in.
		if err := vp.ReadInConfig(); err == nil {
			log.WithField(logfields.Path, vp.ConfigFileUsed()).
				Info("Using config from file")
		} else if Config.ConfigFile != "" {
			log.WithField(logfields.Path, Config.ConfigFile).
				Fatal("Error reading config file")
		} else {
			log.WithError(err).Debug("Skipped reading configuration file")
		}

		// Check for the debug flag again now that the configuration file may has
		// been loaded, as it might have changed.
		if vp.GetBool("debug") {
			logging.SetLogLevelToDebug()
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

// BPFEventBufferConfig contains parsed configuration for a bpf map event buffer.
type BPFEventBufferConfig struct {
	Enabled bool
	MaxSize int
	TTL     time.Duration
}

// BPFEventBufferConfigs contains parsed bpf event buffer configs, indexed but map name.
type BPFEventBufferConfigs map[string]BPFEventBufferConfig

// GetEventBufferConfig returns either the relevant config for a map name, or a default
// one with enabled=false otherwise.
func (d *DaemonConfig) GetEventBufferConfig(name string) BPFEventBufferConfig {
	return d.bpfMapEventConfigs.get(name)
}

func (cs BPFEventBufferConfigs) get(name string) BPFEventBufferConfig {
	return cs[name]
}

// ParseEventBufferTupleString parses a event buffer configuration tuple string.
// For example: true,100,24h
// Which refers to enabled=true, maxSize=100, ttl=24hours.
func ParseEventBufferTupleString(optsStr string) (BPFEventBufferConfig, error) {
	opts := strings.Split(optsStr, ",")
	enabled := false
	conf := BPFEventBufferConfig{}
	if len(opts) != 3 {
		return conf, fmt.Errorf("unexpected event buffer config value format, should be in format 'mapname=enabled,100,24h'")
	}

	if opts[0] != "enabled" && opts[0] != "disabled" {
		return conf, fmt.Errorf("could not parse event buffer enabled: must be either 'enabled' or 'disabled'")
	}
	if opts[0] == "enabled" {
		enabled = true
	}
	size, err := strconv.Atoi(opts[1])
	if err != nil {
		return conf, fmt.Errorf("could not parse event buffer maxSize int: %w", err)
	}
	ttl, err := time.ParseDuration(opts[2])
	if err != nil {
		return conf, fmt.Errorf("could not parse event buffer ttl duration: %w", err)
	}
	if size < 0 {
		return conf, fmt.Errorf("event buffer max size cannot be less than zero (%d)", conf.MaxSize)
	}
	conf.TTL = ttl
	conf.Enabled = enabled && size != 0
	conf.MaxSize = size
	return conf, nil
}

func parseBPFMapEventConfigs(confs BPFEventBufferConfigs, confMap map[string]string) error {
	for name, confStr := range confMap {
		conf, err := ParseEventBufferTupleString(confStr)
		if err != nil {
			return fmt.Errorf("unable to parse %s: %w", BPFMapEventBuffers, err)
		}
		confs[name] = conf
	}
	return nil
}

func (d *DaemonConfig) EnforceLXCFibLookup() bool {
	// See https://github.com/cilium/cilium/issues/27343 for the symptoms.
	//
	// We want to enforce FIB lookup if EndpointRoutes are enabled, because
	// this was a config dependency change which caused different behaviour
	// since v1.14.0-snapshot.2. We will remove this hack later, once we
	// have auto-device detection on by default.
	return d.EnableEndpointRoutes
}

func (d *DaemonConfig) GetZone(id uint8) string {
	return d.ReverseFixedZoneMapping[id]
}

func (d *DaemonConfig) GetZoneID(zone string) uint8 {
	return d.FixedZoneMapping[zone]
}

// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package option

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/spf13/viper"
)

const (
	// AccessLog is the path to access log of supported L7 requests observed
	AccessLog = "access-log"

	// AgentLabels are additional labels to identify this agent
	AgentLabels = "agent-labels"

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

	// BPFRoot is the Path to BPF filesystem
	BPFRoot = "bpf-root"

	// CGroupRoot is the path to Cgroup2 filesystem
	CGroupRoot = "cgroup-root"

	// ConfigFile is the Configuration file (default "$HOME/ciliumd.yaml")
	ConfigFile = "config"

	// ConntrackGarbageCollectorInterval is the garbage collection interval for
	// the connection tracking table (in seconds)
	ConntrackGarbageCollectorInterval = "conntrack-garbage-collector-interval"

	// ContainerRuntime sets the container runtime(s) used by Cilium
	// { containerd | crio | docker | none | auto } ( "auto" uses the container
	// runtime found in the order: "docker", "containerd", "crio" )
	ContainerRuntime = "container-runtime"

	// ContainerRuntimeEndpoint set the container runtime(s) endpoint(s)
	ContainerRuntimeEndpoint = "container-runtime-endpoint"

	// DebugArg is the argument enables debugging mode
	DebugArg = "debug"

	// DebugVerbose is the argument enables verbose log message for particular subsystems
	DebugVerbose = "debug-verbose"

	// Device facing cluster/external network for direct L3 (non-overlay mode)
	Device = "device"

	// DisableConntrack disables connection tracking
	DisableConntrack = "disable-conntrack"

	// DisableEnvoyVersionCheck do not perform Envoy binary version check on startup
	DisableEnvoyVersionCheck = "disable-envoy-version-check"

	// Docker is the path to docker runtime socket (DEPRECATED: use container-runtime-endpoint instead)
	Docker = "docker"

	// EnablePolicy enables policy enforcement in the agent.
	EnablePolicy = "enable-policy"

	// EnableTracing enables tracing mode in the agent.
	EnableTracing = "enable-tracing"

	// EnvoyLog sets the path to a separate Envoy log file, if any
	EnvoyLog = "envoy-log"

	// FixedIdentityMapping is the key-value for the fixed identity mapping
	// which allows to use reserved label for fixed identities
	FixedIdentityMapping = "fixed-identity-mapping"

	// IPv4ClusterCIDRMaskSize is the mask size for the cluster wide CIDR
	IPv4ClusterCIDRMaskSize = "ipv4-cluster-cidr-mask-size"

	// IPv4Range is the per-node IPv4 endpoint prefix, e.g. 10.16.0.0/16
	IPv4Range = "ipv4-range"

	// IPv6Range is the per-node IPv6 endpoint prefix, must be /96, e.g. fd02:1:1::/96
	IPv6Range = "ipv6-range"

	// IPv4ServiceRange is the Kubernetes IPv4 services CIDR if not inside cluster prefix
	IPv4ServiceRange = "ipv4-service-range"

	// IPv6ServiceRange is the Kubernetes IPv6 services CIDR if not inside cluster prefix
	IPv6ServiceRange = "ipv6-service-range"

	// ModePreFilterNative for loading progs with xdpdrv
	ModePreFilterNative = "native"

	// ModePreFilterGeneric for loading progs with xdpgeneric
	ModePreFilterGeneric = "generic"

	// IPv6ClusterAllocCIDRName is the name of the IPv6ClusterAllocCIDR option
	IPv6ClusterAllocCIDRName = "ipv6-cluster-alloc-cidr"

	// K8sRequireIPv4PodCIDRName is the name of the K8sRequireIPv4PodCIDR option
	K8sRequireIPv4PodCIDRName = "k8s-require-ipv4-pod-cidr"

	// K8sRequireIPv6PodCIDRName is the name of the K8sRequireIPv6PodCIDR option
	K8sRequireIPv6PodCIDRName = "k8s-require-ipv6-pod-cidr"

	// K8sAPIServer is the kubernetes api address server (for https use --k8s-kubeconfig-path instead)
	K8sAPIServer = "k8s-api-server"

	// K8sKubeConfigPath is the absolute path of the kubernetes kubeconfig file
	K8sKubeConfigPath = "k8s-kubeconfig-path"

	// KeepConfig when restoring state, keeps containers' configuration in place
	KeepConfig = "keep-config"

	// KeepBPFTemplates do not restore BPF template files from binary
	KeepBPFTemplates = "keep-bpf-templates"

	// KVStore key-value store type
	KVStore = "kvstore"

	// KVStoreOpt key-value store options
	KVStoreOpt = "kvstore-opt"

	// Labels is the list of label prefixes used to determine identity of an endpoint
	Labels = "labels"

	// LabelPrefixFile is the valid label prefixes file path
	LabelPrefixFile = "label-prefix-file"

	// LB enables load balancer mode where load balancer bpf program is attached to the given interface
	LB = "lb"

	// LibDir enables the directory path to store runtime build environment
	LibDir = "lib-dir"

	// LogDriver sets logging endpoints to use for example syslog, fluentd
	LogDriver = "log-driver"

	// LogOpt sets log driver options for cilium
	LogOpt = "log-opt"

	// Logstash enables logstash integration
	Logstash = "logstash"

	// NAT46Range is the IPv6 prefix to map IPv4 addresses to
	NAT46Range = "nat46-range"

	// Masquerade are the packets from endpoints leaving the host
	Masquerade = "masquerade"

	// IPv6NodeAddr is the IPv6 address of node
	IPv6NodeAddr = "ipv6-node"

	// IPv4NodeAddr is the IPv4 address of node
	IPv4NodeAddr = "ipv4-node"

	// Restore restores state, if possible, from previous daemon
	Restore = "restore"

	// SidecarHTTPProxy disable host HTTP proxy, assuming proxies in sidecar containers
	SidecarHTTPProxy = "sidecar-http-proxy"

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

	// PrefilterDevice is the device facing external network for XDP prefiltering
	PrefilterDevice = "prefilter-device"

	// PrefilterMode { "+ModePreFilterNative+" | "+ModePreFilterGeneric+" } (default: "+option.ModePreFilterNative+")
	PrefilterMode = "prefilter-mode"

	// PrometheusServeAddr IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	PrometheusServeAddr = "prometheus-serve-addr"

	// PrometheusServeAddrDeprecated IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	PrometheusServeAddrDeprecated = "prometheus-serve-addr-deprecated"

	// CMDRef is the path to cmdref output directory
	CMDRef = "cmdref"

	// ToFQDNsMinTTL is the minimum time, in seconds, to use DNS data for toFQDNs policies.
	ToFQDNsMinTTL = "tofqdns-min-ttl"

	// ToFQDNsProxyPort is the global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port.
	ToFQDNsProxyPort = "tofqdns-proxy-port"

	// ToFQDNsEnablePoller enables proactive polling of DNS names in toFQDNs.matchName rules.
	ToFQDNsEnablePoller = "tofqdns-enable-poller"

	// AutoIPv6NodeRoutesName is the name of the AutoIPv6NodeRoutes option
	AutoIPv6NodeRoutesName = "auto-ipv6-node-routes"

	// MTUName is the name of the MTU option
	MTUName = "mtu"

	// TunnelName is the name of the Tunnel option
	TunnelName = "tunnel"

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

	// ciliumEnvPrefix is the prefix used for environment variables
	ciliumEnvPrefix = "CILIUM_"

	// ClusterName is the name of the ClusterName option
	ClusterName = "cluster-name"

	// ClusterNameEnv is the name of the environment variable of the
	// ClusterName option
	ClusterNameEnv = "CILIUM_CLUSTER_NAME"

	// ClusterIDName is the name of the ClusterID option
	ClusterIDName = "cluster-id"

	// ClusterIDMin is the minimum value of the cluster ID
	ClusterIDMin = 0

	// ClusterIDMax is the maximum value of the cluster ID
	ClusterIDMax = 255

	// ClusterMeshConfigName is the name of the ClusterMeshConfig option
	ClusterMeshConfigName = "clustermesh-config"

	// BPFCompileDebugName is the name of the option to enable BPF compiliation debugging
	BPFCompileDebugName = "bpf-compile-debug"

	// CTMapEntriesGlobalTCP retains the Cilium 1.2 (or earlier) size to
	// minimize disruption during upgrade.
	CTMapEntriesGlobalTCPDefault = 1000000
	CTMapEntriesGlobalAnyDefault = 2 << 17 // 256Ki
	CTMapEntriesGlobalTCPName    = "bpf-ct-global-tcp-max"
	CTMapEntriesGlobalAnyName    = "bpf-ct-global-any-max"

	// LogSystemLoadConfigName is the name of the option to enable system
	// load loggging
	LogSystemLoadConfigName = "log-system-load"

	// PrependIptablesChainsName is the name of the option to enable
	// prepending iptables chains instead of appending
	PrependIptablesChainsName = "prepend-iptables-chains"

	// DisableCiliumEndpointCRDName is the name of the option to disable
	// use of the CEP CRD
	DisableCiliumEndpointCRDName = "disable-endpoint-crd"

	// DisableK8sServices disables east-west K8s load balancing by cilium
	DisableK8sServices = "disable-k8s-services"

	// MaxCtrlIntervalName and MaxCtrlIntervalNameEnv allow configuration
	// of MaxControllerInterval.
	MaxCtrlIntervalName = "max-controller-interval"

	// SockopsEnableName is the name of the option to enable sockops
	SockopsEnableName = "sockops-enable"

	// K8sNamespaceName is the name of the K8sNamespace option
	K8sNamespaceName = "k8s-namespace"

	// EnableIPv4Name is the name of the option to enable IPv4 support
	EnableIPv4Name = "enable-ipv4"

	// LegacyDisableIPv4Name is the name of the legacy option to disable
	// IPv4 support
	LegacyDisableIPv4Name = "disable-ipv4"

	// EnableIPv6Name is the name of the option to enable IPv6 support
	EnableIPv6Name = "enable-ipv6"

	// MonitorQueueSizeName is the name of the option MonitorQueueSize
	MonitorQueueSizeName = "monitor-queue-size"
)

// Available option for daemonConfig.Tunnel
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
	_, ok := RegisteredOptions[optName]
	if ok || optName == "" {
		panic(fmt.Errorf("option already registered: %s", optName))
	}
	RegisteredOptions[optName] = struct{}{}
	viper.BindEnv(optName, getEnvName(optName))
}

// daemonConfig is the configuration used by Daemon.
type daemonConfig struct {
	BpfDir          string     // BPF template files directory
	LibDir          string     // Cilium library files directory
	RunDir          string     // Cilium runtime directory
	NAT46Prefix     *net.IPNet // NAT46 IPv6 Prefix
	Device          string     // Receive device
	DevicePreFilter string     // XDP device
	ModePreFilter   string     // XDP mode, values: { native | generic }
	HostV4Addr      net.IP     // Host v4 address of the snooping device
	HostV6Addr      net.IP     // Host v6 address of the snooping device
	LBInterface     string     // Set with name of the interface to loadbalance packets from
	Workloads       []string   // List of Workloads set by the user to used by cilium.

	Tunnel string // Tunnel mode

	DryMode bool // Do not create BPF maps, devices, ..

	// RestoreState enables restoring the state from previous running daemons.
	RestoreState bool

	// EnableHostIPRestore enables restoring the host IPs based on state
	// left behind by previous Cilium runs.
	EnableHostIPRestore bool

	KeepConfig    bool // Keep configuration of existing endpoints when starting up.
	KeepTemplates bool // Do not overwrite the template files

	// AllowLocalhost defines when to allows the local stack to local endpoints
	// values: { auto | always | policy }
	AllowLocalhost string

	// HostAllowsWorld applies the same policy to world-sourced traffic as
	// host-sourced traffic, to provide compatibility with Cilium 1.0.
	HostAllowsWorld bool

	// StateDir is the directory where runtime state of endpoints is stored
	StateDir string

	// Options changeable at runtime
	Opts *IntOptions

	// Mutex for serializing configuration updates to the daemon.
	ConfigPatchMutex lock.RWMutex

	// Monitor contains the configuration for the node monitor.
	Monitor *models.MonitorStatus

	// AccessLog is the path to the access log of supported L7 requests observed.
	AccessLog string

	// AgentLabels contains additional labels to identify this agent in monitor events.
	AgentLabels []string

	// IPv6ClusterAllocCIDR is the base CIDR used to allocate IPv6 node
	// CIDRs if allocation is not performed by an orchestration system
	IPv6ClusterAllocCIDR string

	// IPv6ClusterAllocCIDRBase is derived from IPv6ClusterAllocCIDR and
	// contains the CIDR without the mask, e.g. "fdfd::1/64" -> "fdfd::"
	//
	// This variable should never be written to, it is initialized via
	// daemonConfig.Validate()
	IPv6ClusterAllocCIDRBase string

	// K8sRequireIPv4PodCIDR requires the k8s node resource to specify the
	// IPv4 PodCIDR. Cilium will block bootstrapping until the information
	// is available.
	K8sRequireIPv4PodCIDR bool

	// K8sRequireIPv6PodCIDR requires the k8s node resource to specify the
	// IPv6 PodCIDR. Cilium will block bootstrapping until the information
	// is available.
	K8sRequireIPv6PodCIDR bool

	// AutoIPv6NodeRoutes enables automatic route injection of IPv6
	// endpoint routes based on node discovery information
	AutoIPv6NodeRoutes bool

	// MTU is the maximum transmission unit of the underlying network
	MTU int

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

	// DisableCiliumEndpointCRD disables the use of CiliumEndpoint CRD
	DisableCiliumEndpointCRD bool

	// MaxControllerInterval is the maximum value for a controller's
	// RunInterval. Zero means unlimited.
	MaxControllerInterval int

	// UseSingleClusterRoute specifies whether to use a single cluster route
	// instead of per-node routes.
	UseSingleClusterRoute bool

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

	// BPFCompilationDebug specifies whether to compile BPF programs compilation
	// debugging enabled.
	BPFCompilationDebug bool

	// EnvoyLogPath specifies where to store the Envoy proxy logs when Envoy
	// runs in the same container as Cilium.
	EnvoyLogPath string

	// EnableSockOps specifies whether to enable sockops (socket lookup).
	SockopsEnable bool

	// PrependIptablesChains is the name of the option to enable prepending
	// iptables chains instead of appending
	PrependIptablesChains bool

	// K8sNamespace is the name of the namespace in which Cilium is
	// deployed in when running in Kubernetes mode
	K8sNamespace string

	// EnableIPv4 is true when IPv4 is enabled
	EnableIPv4 bool

	// EnableIPv6 is true when IPv6 is enabled
	EnableIPv6 bool

	// MonitorQueueSize is the size of the monitor event queue
	MonitorQueueSize int
}

var (
	Config = &daemonConfig{
		Opts:                     NewIntOptions(&DaemonOptionLibrary),
		Monitor:                  &models.MonitorStatus{Cpus: int64(runtime.NumCPU()), Npages: 64, Pagesize: int64(os.Getpagesize()), Lost: 0, Unknown: 0},
		IPv6ClusterAllocCIDR:     defaults.IPv6ClusterAllocCIDR,
		IPv6ClusterAllocCIDRBase: defaults.IPv6ClusterAllocCIDRBase,
		EnableHostIPRestore:      defaults.EnableHostIPRestore,
		EnableIPv4:               defaults.EnableIPv4,
		EnableIPv6:               defaults.EnableIPv6,
	}
)

func (c *daemonConfig) IsLBEnabled() bool {
	return c.LBInterface != ""
}

// GetNodeConfigPath returns the full path of the NodeConfigFile.
func (c *daemonConfig) GetNodeConfigPath() string {
	return filepath.Join(c.GetGlobalsDir(), common.NodeConfigFile)
}

// GetGlobalsDir returns the path for the globals directory.
func (c *daemonConfig) GetGlobalsDir() string {
	return filepath.Join(c.StateDir, "globals")
}

// WorkloadsEnabled returns true if any workload runtimes are enabled
func (c *daemonConfig) WorkloadsEnabled() bool {
	for _, w := range c.Workloads {
		if w == "none" {
			return false
		}
	}

	return len(c.Workloads) > 0
}

// AlwaysAllowLocalhost returns true if the daemon has the option set that
// localhost can always reach local endpoints
func (c *daemonConfig) AlwaysAllowLocalhost() bool {
	switch c.AllowLocalhost {
	case AllowLocalhostAlways:
		return true
	case AllowLocalhostAuto, AllowLocalhostPolicy:
		return false
	default:
		return false
	}
}

// TracingEnabled returns if tracing policy (outlining which rules apply to a
// specific set of labels) is enabled.
func (c *daemonConfig) TracingEnabled() bool {
	return c.Opts.IsEnabled(PolicyTracing)
}

func (c *daemonConfig) validateIPv6ClusterAllocCIDR() error {
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
func (c *daemonConfig) Validate() error {
	if err := c.validateIPv6ClusterAllocCIDR(); err != nil {
		return fmt.Errorf("unable to parse CIDR value '%s' of option --%s: %s",
			c.IPv6ClusterAllocCIDR, IPv6ClusterAllocCIDRName, err)
	}

	if c.MTU < 0 {
		return fmt.Errorf("MTU '%d' cannot be negative", c.MTU)
	}

	switch c.Tunnel {
	case TunnelVXLAN, TunnelGeneve:
	case TunnelDisabled:
		if c.UseSingleClusterRoute {
			return fmt.Errorf("option --%s cannot be used in combination with --%s=%s",
				SingleClusterRouteName, TunnelName, TunnelDisabled)
		}
	default:
		return fmt.Errorf("invalid tunnel mode '%s', valid modes = {%s}", c.Tunnel, GetTunnelModes())
	}

	if c.ClusterID < ClusterIDMin || c.ClusterID > ClusterIDMax {
		return fmt.Errorf("invalid cluster id %d: must be in range %d..%d",
			c.ClusterID, ClusterIDMin, ClusterIDMax)
	}

	if c.ClusterID != 0 {
		if c.ClusterName == defaults.ClusterName {
			return fmt.Errorf("cannot use default cluster name (%s) with option %s",
				defaults.ClusterName, ClusterIDName)
		}
	}

	ctTableMin := 1 << 10 // 1Ki entries
	ctTableMax := 1 << 24 // 16Mi entries (~1GiB of entries per map)
	if c.CTMapEntriesGlobalTCP < ctTableMin || c.CTMapEntriesGlobalAny < ctTableMin {
		return fmt.Errorf("Specified CT tables values %d/%d must exceed minimum %d",
			c.CTMapEntriesGlobalTCP, c.CTMapEntriesGlobalAny, ctTableMin)
	}
	if c.CTMapEntriesGlobalTCP > ctTableMax || c.CTMapEntriesGlobalAny > ctTableMax {
		return fmt.Errorf("Specified CT tables values %d/%d must not exceed maximum %d",
			c.CTMapEntriesGlobalTCP, c.CTMapEntriesGlobalAny, ctTableMax)
	}

	return nil
}

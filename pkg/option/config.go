// Copyright 2016-2019 Authors of Cilium
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
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "config")
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

	// ConfigDir is the directory that contains a file for each option where
	// the filename represents the option name and the content of that file
	// represents the value of that option.
	ConfigDir = "config-dir"

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

	// K8sLegacyHostAllowsWorld is the legacy option to that allows policy host to talk with world
	K8sLegacyHostAllowsWorld = "k8s-legacy-host-allows-world"

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

	// InstallIptRules sets whether Cilium should install any iptables in general
	InstallIptRules = "install-iptables-rules"

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

	// FlannelMasterDevice installs a BPF program to allow for policy
	// enforcement in the given network interface. Allows to run Cilium on top
	// of other CNI plugins that provide networking, e.g. flannel, where for
	// flannel, this value should be set with 'cni0'. [EXPERIMENTAL]")
	FlannelMasterDevice = "flannel-master-device"

	// FlannelUninstallOnExit should be used along the flannel-master-device flag,
	// it cleans up all BPF programs installed when Cilium agent is terminated.
	FlannelUninstallOnExit = "flannel-uninstall-on-exit"

	// FlannelManageExistingContainers sets if Cilium should install the BPF
	// programs on already running interfaces created by flannel. Require
	// Cilium to be running in the hostPID.
	FlannelManageExistingContainers = "flannel-manage-existing-containers"

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

	// ToFQDNsEmitPollerEvents controls if poller lookups are sent as monitor events
	ToFQDNsEnablePollerEvents = "tofqdns-enable-poller-events"

	// ToFQDNsMaxIPsPerHost defines the maximum number of IPs to maintain
	// for each FQDN name in an endpoint's FQDN cache
	ToFQDNsMaxIPsPerHost = "tofqdns-endpoint-max-ip-per-hostname"

	// ToFQDNsPreCache is a path to a file with DNS cache data to insert into the
	// global cache on startup.
	// The file is not re-read after agent start.
	ToFQDNsPreCache = "tofqdns-pre-cache"

	// AutoIPv6NodeRoutesName is the name of the AutoIPv6NodeRoutes option
	AutoIPv6NodeRoutesName = "auto-ipv6-node-routes"

	// LegacyAutoIPv6NodeRoutesName is the name of the AutoIPv6NodeRoutes option
	LegacyAutoIPv6NodeRoutesName = "auto-ipv6-node-routes"

	// MTUName is the name of the MTU option
	MTUName = "mtu"

	// DatapathMode is the name of the DatapathMode option
	DatapathMode = "datapath-mode"

	// IpvlanMasterDevice is the name of the IpvlanMasterDevice option
	IpvlanMasterDevice = "ipvlan-master-device"

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

	// PreAllocateMapsName is the name of the option PreAllocateMaps
	PreAllocateMapsName = "preallocate-bpf-maps"

	// EnableAutoDirectRoutingName is the name for the EnableAutoDirectRouting option
	EnableAutoDirectRoutingName = "auto-direct-node-routes"

	// EnableIPSecName is the name of the option to enable IPSec
	EnableIPSecName = "enable-ipsec"

	// IPSecKeyFileName is the name of the option for ipsec key file
	IPSecKeyFileName = "ipsec-key-file"
)

// FQDNS variables
var (
	FQDNRejectOptions = []string{FQDNProxyDenyWithNameError, FQDNProxyDenyWithRefused}
)

// Available option for DaemonConfig.DatapathMode
const (
	// DatapathModeVeth specifies veth datapath mode (i.e. containers are
	// attached to a network via veth pairs)
	DatapathModeVeth = "veth"

	// DatapathModeIpvlan specifies ipvlan datapath mode
	DatapathModeIpvlan = "ipvlan"
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

// Available option for DaemonConfig.Ipvlan.OperationMode
const (
	// OperationModeL3S will respect iptables rules e.g. set up for masquerading
	OperationModeL3S = "L3S"

	// OperationModeL3 will bypass iptables rules on the host
	OperationModeL3 = "L3"
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

// LogRegisteredOptions logs all options that where bind to viper.
func LogRegisteredOptions(entry *logrus.Entry) {
	keys := make([]string, 0, len(RegisteredOptions))
	for k := range RegisteredOptions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		entry.Infof("  --%s='%s'", k, viper.GetString(k))
	}
}

// IpvlanConfig is the configuration used by Daemon when in ipvlan mode.
type IpvlanConfig struct {
	MasterDeviceIndex int
	OperationMode     string
}

// DaemonConfig is the configuration used by Daemon.
type DaemonConfig struct {
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

	Ipvlan IpvlanConfig // Ipvlan related configuration

	DatapathMode string // Datapath mode
	Tunnel       string // Tunnel mode

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

	// EnableIPSec is true when IPSec is enabled
	EnableIPSec bool

	// IPSec key file for stored keys
	IPSecKeyFile string

	// MonitorQueueSize is the size of the monitor event queue
	MonitorQueueSize int

	// CLI options

	BPFRoot                           string
	CGroupRoot                        string
	BPFCompileDebug                   string
	ConfigFile                        string
	ConfigDir                         string
	ConntrackGarbageCollectorInterval int
	ContainerRuntimeEndpoint          map[string]string
	Debug                             bool
	DebugVerbose                      []string
	DisableConntrack                  bool
	DisableK8sServices                bool
	DockerEndpoint                    string
	EnablePolicy                      string
	EnableTracing                     bool
	EnvoyLog                          string
	DisableEnvoyVersionCheck          bool
	FixedIdentityMapping              map[string]string
	FixedIdentityMappingValidator     func(val string) (string, error)
	IPv4ClusterCIDRMaskSize           int
	IPv4Range                         string
	IPv6Range                         string
	IPv4ServiceRange                  string
	IPv6ServiceRange                  string
	K8sAPIServer                      string
	K8sKubeConfigPath                 string
	K8sLegacyHostAllowsWorld          string
	KVStore                           string
	KVStoreOpt                        map[string]string
	LabelPrefixFile                   string
	Labels                            []string
	LogDriver                         []string
	LogOpt                            map[string]string
	Logstash                          bool
	LogSystemLoadConfig               bool
	NAT46Range                        string

	// Masquerade specifies whether or not to masquerade packets from endpoints
	// leaving the host.
	Masquerade             bool
	InstallIptRules        bool
	MonitorAggregation     string
	PreAllocateMaps        bool
	IPv6NodeAddr           string
	IPv4NodeAddr           string
	SidecarHTTPProxy       bool
	SidecarIstioProxyImage string
	SocketPath             string
	TracePayloadlen        int
	Version                string
	PProf                  bool
	PrometheusServeAddr    string
	CMDRefDir              string
	ToFQDNsMinTTL          int

	// ToFQDNsProxyPort is the user-configured global, shared, DNS listen port used
	// by the DNS Proxy. Both UDP and TCP are handled on the same port. When it
	// is 0 a random port will be assigned, and can be obtained from
	// DefaultDNSProxy below.
	ToFQDNsProxyPort int

	// ToFQDNsEnablePoller enables the DNS poller that polls toFQDNs.matchName
	ToFQDNsEnablePoller bool

	// ToFQDNsEnablePollerEvents controls sending a monitor event for each DNS
	// response the DNS poller sees
	ToFQDNsEnablePollerEvents bool

	// ToFQDNsMaxIPsPerHost defines the maximum number of IPs to maintain
	// for each FQDN name in an endpoint's FQDN cache
	ToFQDNsMaxIPsPerHost int

	// FQDNRejectResponse is the dns-proxy response for invalid dns-proxy request
	FQDNRejectResponse string

	// Path to a file with DNS cache data to preload on startup
	ToFQDNsPreCache string

	// HostDevice will be device used by Cilium to connect to the outside world.
	HostDevice string

	// FlannelMasterDevice installs a BPF program in the given interface
	// to allow for policy enforcement mode on top of flannel.
	FlannelMasterDevice string

	// FlannelUninstallOnExit removes the BPF programs that were installed by
	// Cilium on all interfaces created by the flannel.
	FlannelUninstallOnExit bool

	// FlannelManageExistingContainers sets if Cilium should install the BPF
	// programs on already running interfaces created by flannel. Require
	// Cilium to be running in the hostPID.
	FlannelManageExistingContainers bool

	// EnableAutoDirectRouting enables installation of direct routes to
	// other nodes when available
	EnableAutoDirectRouting bool

	// EnableHealthChecking enables health checking between nodes and
	// health endpoints
	EnableHealthChecking bool
}

var (
	// Config represents the daemon configuration
	Config = &DaemonConfig{
		Opts:                     NewIntOptions(&DaemonOptionLibrary),
		Monitor:                  &models.MonitorStatus{Cpus: int64(runtime.NumCPU()), Npages: 64, Pagesize: int64(os.Getpagesize()), Lost: 0, Unknown: 0},
		IPv6ClusterAllocCIDR:     defaults.IPv6ClusterAllocCIDR,
		IPv6ClusterAllocCIDRBase: defaults.IPv6ClusterAllocCIDRBase,
		EnableHostIPRestore:      defaults.EnableHostIPRestore,
		EnableHealthChecking:     defaults.EnableHealthChecking,
		EnableIPv4:               defaults.EnableIPv4,
		EnableIPv6:               defaults.EnableIPv6,
		ToFQDNsMaxIPsPerHost:     defaults.ToFQDNsMaxIPsPerHost,
		ContainerRuntimeEndpoint: make(map[string]string),
		FixedIdentityMapping:     make(map[string]string),
		KVStoreOpt:               make(map[string]string),
		LogOpt:                   make(map[string]string),
	}
)

// IsLBEnabled returns true if LB should be enabled
func (c *DaemonConfig) IsLBEnabled() bool {
	return c.LBInterface != ""
}

// GetNodeConfigPath returns the full path of the NodeConfigFile.
func (c *DaemonConfig) GetNodeConfigPath() string {
	return filepath.Join(c.GetGlobalsDir(), common.NodeConfigFile)
}

// GetGlobalsDir returns the path for the globals directory.
func (c *DaemonConfig) GetGlobalsDir() string {
	return filepath.Join(c.StateDir, "globals")
}

// WorkloadsEnabled returns true if any workload runtimes are enabled
func (c *DaemonConfig) WorkloadsEnabled() bool {
	for _, w := range c.Workloads {
		if w == "none" {
			return false
		}
	}

	return len(c.Workloads) > 0
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

// TracingEnabled returns if tracing policy (outlining which rules apply to a
// specific set of labels) is enabled.
func (c *DaemonConfig) TracingEnabled() bool {
	return c.Opts.IsEnabled(PolicyTracing)
}

// IsFlannelMasterDeviceSet returns if the flannel master device is set.
func (c *DaemonConfig) IsFlannelMasterDeviceSet() bool {
	return len(c.FlannelMasterDevice) != 0
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

// ReadDirConfig reads the given directory and returns a map that maps the
// filename to the contents of that file.
func ReadDirConfig(dirName string) (map[string]interface{}, error) {
	m := map[string]interface{}{}
	fi, err := ioutil.ReadDir(dirName)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to read configuration directory: %s", err)
	}
	for _, f := range fi {
		if f.Mode().IsDir() {
			continue
		}
		fName := filepath.Join(dirName, f.Name())

		// the file can still be a symlink to a directory
		if f.Mode()&os.ModeSymlink == 0 {
			absFileName, err := filepath.EvalSymlinks(fName)
			if err != nil {
				log.Warnf("Unable to read configuration file %q: %s", absFileName, err)
				continue
			}
			fName = absFileName
		}

		f, err = os.Stat(fName)
		if err != nil {
			log.Warnf("Unable to read configuration file %q: %s", fName, err)
			continue
		}
		if f.Mode().IsDir() {
			continue
		}

		b, err := ioutil.ReadFile(fName)
		if err != nil {
			log.Warnf("Unable to read configuration file %q: %s", fName, err)
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
		"legacy-host-allows-world":    K8sLegacyHostAllowsWorld,
	}
	for deprecatedOption, newOption := range deprecatedFields {
		if deprecatedValue, ok := m[deprecatedOption]; ok {
			if _, ok := m[newOption]; !ok {
				m[newOption] = deprecatedValue
			}
		}
	}
}

// Populate sets all options with the values from viper
func (c *DaemonConfig) Populate() {
	c.AccessLog = viper.GetString(AccessLog)
	c.AgentLabels = viper.GetStringSlice(AgentLabels)
	c.AllowLocalhost = viper.GetString(AllowLocalhost)
	c.BPFCompilationDebug = viper.GetBool(BPFCompileDebugName)
	c.CTMapEntriesGlobalTCP = viper.GetInt(CTMapEntriesGlobalTCPName)
	c.CTMapEntriesGlobalAny = viper.GetInt(CTMapEntriesGlobalAnyName)
	c.BPFRoot = viper.GetString(BPFRoot)
	c.CGroupRoot = viper.GetString(CGroupRoot)
	c.ClusterID = viper.GetInt(ClusterIDName)
	c.ClusterName = viper.GetString(ClusterName)
	c.ClusterMeshConfig = viper.GetString(ClusterMeshConfigName)
	c.ConntrackGarbageCollectorInterval = viper.GetInt(ConntrackGarbageCollectorInterval)
	c.DatapathMode = viper.GetString(DatapathMode)
	c.Debug = viper.GetBool(DebugArg)
	c.DebugVerbose = viper.GetStringSlice(DebugVerbose)
	c.Device = viper.GetString(Device)
	c.DisableConntrack = viper.GetBool(DisableConntrack)
	c.EnableIPv4 = getIPv4Enabled()
	c.EnableIPv6 = viper.GetBool(EnableIPv6Name)
	c.EnableIPSec = viper.GetBool(EnableIPSecName)
	c.DevicePreFilter = viper.GetString(PrefilterDevice)
	c.DisableCiliumEndpointCRD = viper.GetBool(DisableCiliumEndpointCRDName)
	c.DisableK8sServices = viper.GetBool(DisableK8sServices)
	c.DockerEndpoint = viper.GetString(Docker)
	c.EnableAutoDirectRouting = viper.GetBool(EnableAutoDirectRoutingName)
	c.EnablePolicy = strings.ToLower(viper.GetString(EnablePolicy))
	c.EnableTracing = viper.GetBool(EnableTracing)
	c.EnvoyLogPath = viper.GetString(EnvoyLog)
	c.HostDevice = getHostDevice()
	c.HTTPIdleTimeout = viper.GetInt(HTTPIdleTimeout)
	c.HTTPMaxGRPCTimeout = viper.GetInt(HTTPMaxGRPCTimeout)
	c.HTTPRequestTimeout = viper.GetInt(HTTPRequestTimeout)
	c.HTTPRetryCount = viper.GetInt(HTTPRetryCount)
	c.HTTPRetryTimeout = viper.GetInt(HTTPRetryTimeout)
	c.IPv4ClusterCIDRMaskSize = viper.GetInt(IPv4ClusterCIDRMaskSize)
	c.IPv4Range = viper.GetString(IPv4Range)
	c.IPv4NodeAddr = viper.GetString(IPv4NodeAddr)
	c.IPv4ServiceRange = viper.GetString(IPv4ServiceRange)
	c.IPv6ClusterAllocCIDR = viper.GetString(IPv6ClusterAllocCIDRName)
	c.IPv6NodeAddr = viper.GetString(IPv6NodeAddr)
	c.IPv6Range = viper.GetString(IPv6Range)
	c.IPv6ServiceRange = viper.GetString(IPv6ServiceRange)
	c.K8sAPIServer = viper.GetString(K8sAPIServer)
	c.K8sKubeConfigPath = viper.GetString(K8sKubeConfigPath)
	c.K8sRequireIPv4PodCIDR = viper.GetBool(K8sRequireIPv4PodCIDRName)
	c.K8sRequireIPv6PodCIDR = viper.GetBool(K8sRequireIPv6PodCIDRName)
	c.KeepTemplates = viper.GetBool(KeepBPFTemplates)
	c.KeepConfig = viper.GetBool(KeepConfig)
	c.KVStore = viper.GetString(KVStore)
	c.LabelPrefixFile = viper.GetString(LabelPrefixFile)
	c.Labels = viper.GetStringSlice(Labels)
	c.LBInterface = viper.GetString(LB)
	c.LibDir = viper.GetString(LibDir)
	c.LogDriver = viper.GetStringSlice(LogDriver)
	c.LogSystemLoadConfig = viper.GetBool(LogSystemLoadConfigName)
	c.Logstash = viper.GetBool(Logstash)
	c.Masquerade = viper.GetBool(Masquerade)
	c.InstallIptRules = viper.GetBool(InstallIptRules)
	c.ModePreFilter = viper.GetString(PrefilterMode)
	c.MonitorAggregation = viper.GetString(MonitorAggregationName)
	c.MonitorQueueSize = viper.GetInt(MonitorQueueSizeName)
	c.MTU = viper.GetInt(MTUName)
	c.NAT46Range = viper.GetString(NAT46Range)
	c.FlannelMasterDevice = viper.GetString(FlannelMasterDevice)
	c.FlannelUninstallOnExit = viper.GetBool(FlannelUninstallOnExit)
	c.FlannelManageExistingContainers = viper.GetBool(FlannelManageExistingContainers)
	c.PProf = viper.GetBool(PProf)
	c.PreAllocateMaps = viper.GetBool(PreAllocateMapsName)
	c.PrependIptablesChains = viper.GetBool(PrependIptablesChainsName)
	c.PrometheusServeAddr = getPrometheusServerAddr()
	c.ProxyConnectTimeout = viper.GetInt(ProxyConnectTimeout)
	c.RestoreState = viper.GetBool(Restore)
	c.RunDir = viper.GetString(StateDir)
	c.SidecarIstioProxyImage = viper.GetString(SidecarIstioProxyImage)
	c.UseSingleClusterRoute = viper.GetBool(SingleClusterRouteName)
	c.SocketPath = viper.GetString(SocketPath)
	c.SockopsEnable = viper.GetBool(SockopsEnableName)
	c.TracePayloadlen = viper.GetInt(TracePayloadlen)
	c.Tunnel = viper.GetString(TunnelName)
	c.Version = viper.GetString(Version)
	c.Workloads = viper.GetStringSlice(ContainerRuntime)

	// This is a legacy option. Provide backward compatibility by enabling
	// automatic direct routing. Unlike the old option, it will also enable
	// direct routing for IPv4. Better than breaking the option. The old
	// option was not frequently used so this addition in scope is fine.
	if viper.GetBool(LegacyAutoIPv6NodeRoutesName) {
		c.EnableAutoDirectRouting = true
	}

	// toFQDNs options
	// When the poller is enabled, the default MinTTL is lowered. This is to
	// avoid caching large sets of identities generated by a poller (it runs
	// every 5s). Without the poller, a longer default is better because it
	// avoids confusion about dropped connections.
	c.ToFQDNsEnablePoller = viper.GetBool(ToFQDNsEnablePoller)
	c.ToFQDNsEnablePollerEvents = viper.GetBool(ToFQDNsEnablePollerEvents)
	c.ToFQDNsMaxIPsPerHost = viper.GetInt(ToFQDNsMaxIPsPerHost)
	userSetMinTTL := viper.GetInt(ToFQDNsMinTTL)
	switch {
	case userSetMinTTL != 0: // set by user
		c.ToFQDNsMinTTL = userSetMinTTL
	case c.ToFQDNsEnablePoller:
		c.ToFQDNsMinTTL = defaults.ToFQDNsMinTTLPoller
	default:
		c.ToFQDNsMinTTL = defaults.ToFQDNsMinTTL
	}
	c.ToFQDNsProxyPort = viper.GetInt(ToFQDNsProxyPort)
	c.ToFQDNsPreCache = viper.GetString(ToFQDNsPreCache)

	// Map options
	if m := viper.GetStringMapString(ContainerRuntimeEndpoint); len(m) != 0 {
		c.ContainerRuntimeEndpoint = m
	}

	if m := viper.GetStringMapString(FixedIdentityMapping); len(m) != 0 {
		c.FixedIdentityMapping = m
	}

	if m := viper.GetStringMapString(KVStoreOpt); len(m) != 0 {
		c.KVStoreOpt = m
	}

	if m := viper.GetStringMapString(LogOpt); len(m) != 0 {
		c.LogOpt = m
	}

	// Hidden options
	c.ConfigFile = viper.GetString(ConfigFile)
	c.HTTP403Message = viper.GetString(HTTP403Message)
	c.DisableEnvoyVersionCheck = viper.GetBool(DisableEnvoyVersionCheck)
	c.K8sNamespace = viper.GetString(K8sNamespaceName)
	c.K8sLegacyHostAllowsWorld = viper.GetString(K8sLegacyHostAllowsWorld)
	c.MaxControllerInterval = viper.GetInt(MaxCtrlIntervalName)
	c.SidecarHTTPProxy = viper.GetBool(SidecarHTTPProxy)
	c.CMDRefDir = viper.GetString(CMDRef)
}

func getIPv4Enabled() bool {
	if viper.GetBool(LegacyDisableIPv4Name) {
		return false
	}

	return viper.GetBool(EnableIPv4Name)
}

func getPrometheusServerAddr() string {
	promAddr := viper.GetString(PrometheusServeAddr)
	if promAddr == "" {
		return viper.GetString("prometheus-serve-addr-deprecated")
	}
	return promAddr
}

func getHostDevice() string {
	hostDevice := viper.GetString(FlannelMasterDevice)
	if hostDevice == "" {
		return defaults.HostDevice
	}
	return hostDevice
}

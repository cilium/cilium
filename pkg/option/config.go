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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
)

const (
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

	// AutoIPv6NodeRoutesName is the name of the AutoIPv6NodeRoutes option
	AutoIPv6NodeRoutesName = "auto-ipv6-node-routes"

	// MTUName is the name of the MTU option
	MTUName = "mtu"

	// TunnelName is the name of the Tunnel option
	TunnelName = "tunnel"

	// TunnelNameEnv is the name of the environment variable for option.TunnelName
	TunnelNameEnv = "CILIUM_TUNNEL"

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

	// ClusterName is the name of the ClusterName option
	ClusterName = "cluster-name"

	// ClusterNameEnv is the name of the environment variable of the
	// ClusterName option
	ClusterNameEnv = "CILIUM_CLUSTER_NAME"

	// ClusterIDName is the name of the ClusterID option
	ClusterIDName = "cluster-id"

	// ClusterIDEnv is the name of the environment variable of the
	// ClusterID option
	ClusterIDEnv = "CILIUM_CLUSTER_ID"

	// ClusterIDMin is the minimum value of the cluster ID
	ClusterIDMin = 0

	// ClusterIDMax is the maximum value of the cluster ID
	ClusterIDMax = 255

	// ClusterIDShift specifies the number of bits the cluster ID will be
	// shifted
	ClusterIDShift = 16

	// ClusterMeshConfigName is the name of the ClusterMeshConfig option
	ClusterMeshConfigName = "clustermesh-config"

	// ClusterMeshConfigNameEnv is the name of the environment variable of
	// the ClusterMeshConfig option
	ClusterMeshConfigNameEnv = "CILIUM_CLUSTERMESH_CONFIG"

	// BPFCompileDebugName is the name of the option to enable BPF compiliation debugging
	BPFCompileDebugName = "bpf-compile-debug"

	// CTMapEntriesGlobalTCP retains the Cilium 1.2 (or earlier) size to
	// minimize disruption during upgrade.
	CTMapEntriesGlobalTCPDefault = 1000000
	CTMapEntriesGlobalAnyDefault = 2 << 17 // 256Ki
	CTMapEntriesGlobalTCPName    = "bpf-ct-global-tcp-max"
	CTMapEntriesGlobalAnyName    = "bpf-ct-global-any-max"
	CTMapEntriesGlobalTCPNameEnv = "CILIUM_GLOBAL_CT_MAX_TCP"
	CTMapEntriesGlobalAnyNameEnv = "CILIUM_GLOBAL_CT_MAX_ANY"

	// LogSystemLoadConfigName is the name of the option to enable system
	// load loggging
	LogSystemLoadConfigName = "log-system-load"

	// PrependIptablesChainsName is the name of the option to enable
	// prepending iptables chains instead of appending
	PrependIptablesChainsName = "prepend-iptables-chains"

	// PrependIptablesChainsNameEnv is the name of the environment variable
	// of the PrependIptablesChainsName option
	PrependIptablesChainsNameEnv = "CILIUM_PREPEND_IPTABLES_CHAIN"

	// DisableCiliumEndpointCRDName is the name of the option to disable
	// use of the CEP CRD
	DisableCiliumEndpointCRDName = "disable-endpoint-crd"

	// MaxCtrlIntervalName and MaxCtrlIntervalNameEnv allow configuration
	// of MaxControllerInterval.
	MaxCtrlIntervalName    = "max-controller-interval"
	MaxCtrlIntervalNameEnv = "CILIUM_MAX_CONTROLLER_INTERVAL"

	// SockopsEnableName is the name of the option to enable sockops
	SockopsEnableName = "sockops-enable"

	// K8sNamespaceName is the name of the K8sNamespace option
	K8sNamespaceName = "k8s-namespace"

	// K8sNamespaceNameEnv is the name of the K8sNamespace environment
	// variable
	K8sNamespaceNameEnv = "CILIUM_K8S_NAMESPACE"

	// EnableIPv4Name is the name of the option to enable IPv4 support
	EnableIPv4Name    = "enable-ipv4"
	EnableIPv4NameEnv = "CILIUM_ENABLE_IPV4"

	// LegacyDisableIPv4Name is the name of the legacy option to disable
	// IPv4 support
	LegacyDisableIPv4Name    = "disable-ipv4"
	LegacyDisableIPv4NameEnv = "DISABLE_IPV4"

	// EnableIPv6Name is the name of the option to enable IPv6 support
	EnableIPv6Name    = "enable-ipv6"
	EnableIPv6NameEnv = "CILIUM_ENABLE_IPV6"
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

	if c.MTU <= 0 {
		return fmt.Errorf("MTU '%d' cannot be 0 or negative", c.MTU)
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

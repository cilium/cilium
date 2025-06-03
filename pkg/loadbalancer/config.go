// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// Configuration option names
const (
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

	// LBSourceRangeAllTypes configures service source ranges for all service types.
	LBSourceRangeAllTypes = "bpf-lb-source-range-all-types"

	// LBSourceRangeMapMaxEntries configures max entries of bpf map for service source ranges.
	LBSourceRangeMapMaxEntries = "bpf-lb-source-range-map-max"

	// LBMaglevMapMaxEntries configures max entries of bpf map for Maglev.
	LBMaglevMapMaxEntries = "bpf-lb-maglev-map-max"

	// SockRevNatEntriesName configures max entries for BPF sock reverse nat
	// entries.
	LBSockRevNatEntriesName = "bpf-sock-rev-map-max"

	// NodePortRange defines a custom range where to look up NodePort services
	NodePortRange = "node-port-range"

	LBAlgorithmName = "bpf-lb-algorithm"

	// Deprecated option for setting [LBAlgorithm]
	NodePortAlgName = "node-port-algorithm"

	// LoadBalancerMode indicates in which mode NodePort implementation should run
	// ("snat", "dsr" or "hybrid")
	LoadBalancerModeName = "bpf-lb-mode"

	// LoadBalancerModeAnnotation tells whether controller should check service
	// level annotation for configuring bpf loadbalancing method (snat vs dsr).
	LoadBalancerModeAnnotationName = "bpf-lb-mode-annotation"

	// Deprecated option for setting [LoadBalancerMode]
	NodePortModeName = "node-port-mode"

	// LoadBalancerDSRDispatchName is the config option for setting the method for
	// pushing packets to backends under DSR ("opt" or "ipip")
	LoadBalancerDSRDispatchName = "bpf-lb-dsr-dispatch"

	// ExternalClusterIPName is the name of the option to enable
	// cluster external access to ClusterIP services.
	ExternalClusterIPName = "bpf-lb-external-clusterip"

	// AlgorithmAnnotationName tells whether controller should check service
	// level annotation for configuring bpf loadbalancing algorithm.
	AlgorithmAnnotationName = "bpf-lb-algorithm-annotation"

	// EnableHealthCheckNodePort is the name of the EnableHealthCheckNodePort option
	EnableHealthCheckNodePortName = "enable-health-check-nodeport"

	// EnableServiceTopologyName is the flag name of for the EnableServiceTopology option
	EnableServiceTopologyName = "enable-service-topology"
)

// Configuration option defaults
const (
	// DefaultLBMapMaxEntries is the default size for the load-balancing BPF maps.
	DefaultLBMapMaxEntries = 65536

	// NodePortMinDefault is the minimal port to listen for NodePort requests
	NodePortMinDefault = 30000

	// NodePortMaxDefault is the maximum port to listen for NodePort requests
	NodePortMaxDefault = 32767
)

const (
	// LBAlgorithmRandom is for randomly selecting a backend
	LBAlgorithmRandom = "random"

	// LBAlgorithmMaglev is for using maglev consistent hashing for backend selection
	LBAlgorithmMaglev = "maglev"

	// LBModeSNAT is for SNATing requests to remote nodes
	LBModeSNAT = "snat"

	// LBModeDSR is for performing DSR for requests to remote nodes
	LBModeDSR = "dsr"

	// LBModeHybrid is a dual mode of the above, that is, DSR for TCP and SNAT for UDP
	LBModeHybrid = "hybrid"

	// DSR dispatch mode to encode service into IP option or extension header
	DSRDispatchOption = "opt"

	// DSR dispatch mode to encapsulate to IPIP
	DSRDispatchIPIP = "ipip"

	// DSR dispatch mode to encapsulate to Geneve
	DSRDispatchGeneve = "geneve"
)

// UserConfig is the configuration provided by the user that has not been processed.
// +deepequal-gen=true
type UserConfig struct {
	RetryBackoffMin time.Duration `mapstructure:"lb-retry-backoff-min"`
	RetryBackoffMax time.Duration `mapstructure:"lb-retry-backoff-max"`

	// LBMapEntries is the maximum number of entries allowed in BPF lbmap.
	LBMapEntries int `mapstructure:"bpf-lb-map-max"`

	// LBServiceMapEntries is the maximum number of entries allowed in BPF lbmap for services.
	LBServiceMapEntries int `mapstructure:"bpf-lb-service-map-max"`

	// LBBackendMapEntries is the maximum number of entries allowed in BPF lbmap for service backends.
	LBBackendMapEntries int `mapstructure:"bpf-lb-service-backend-map-max"`

	// LBRevNatEntries is the maximum number of entries allowed in BPF lbmap for reverse NAT.
	LBRevNatEntries int `mapstructure:"bpf-lb-rev-nat-map-max"`

	// LBAffinityMapEntries is the maximum number of entries allowed in BPF lbmap for session affinities.
	LBAffinityMapEntries int `mapstructure:"bpf-lb-affinity-map-max"`

	// LBSourceRangeAllTypes enables propagation of loadbalancerSourceRanges to all Kubernetes
	// service types which were created from the LoadBalancer service.
	LBSourceRangeAllTypes bool `mapstructure:"bpf-lb-source-range-all-types"`

	// LBSourceRangeMapEntries is the maximum number of entries allowed in BPF lbmap for source ranges.
	LBSourceRangeMapEntries int `mapstructure:"bpf-lb-source-range-map-max"`

	// LBMaglevMapEntries is the maximum number of entries allowed in BPF lbmap for maglev.
	LBMaglevMapEntries int `mapstructure:"bpf-lb-maglev-map-max"`

	// LBSockRevNatEntries is the maximum number of sock rev nat mappings
	// allowed in the BPF rev nat table
	LBSockRevNatEntries int `mapstructure:"bpf-sock-rev-map-max"`

	// NodePortRange is the minimum and maximum ports to use for NodePort
	NodePortRange []string

	// LBMode indicates in which mode NodePort implementation should run
	// ("snat", "dsr" or "hybrid")
	LBMode string `mapstructure:"bpf-lb-mode"`

	// LBModeAnnotation tells whether controller should check service
	// level annotation for configuring bpf load balancing algorithm.
	LBModeAnnotation bool `mapstructure:"bpf-lb-mode-annotation"`

	// LoadBalancerAlgorithm indicates which backend selection algorithm is used
	// ("random" or "maglev")
	LBAlgorithm string `mapstructure:"bpf-lb-algorithm"`

	// DSRDispatch indicates the method for pushing packets to
	// backends under DSR ("opt" or "ipip")
	DSRDispatch string `mapstructure:"bpf-lb-dsr-dispatch"`

	// ExternalClusterIP enables routing to ClusterIP services from outside
	// the cluster. This mirrors the behaviour of kube-proxy.
	ExternalClusterIP bool `mapstructure:"bpf-lb-external-clusterip"`

	// AlgorithmAnnotation tells whether controller should check service
	// level annotation for configuring bpf load balancing algorithm.
	AlgorithmAnnotation bool `mapstructure:"bpf-lb-algorithm-annotation"`

	// EnableHealthCheckNodePort enables health checking of NodePort by
	// cilium
	EnableHealthCheckNodePort bool `mapstructure:"enable-health-check-nodeport"`

	// LBPressureMetricsInterval sets the interval for updating the load-balancer BPF map
	// pressure metrics. A batch lookup is performed for all maps periodically to count
	// the number of elements that are then reported in the `bpf-map-pressure` metric.
	LBPressureMetricsInterval time.Duration `mapstructure:"lb-pressure-metrics-interval"`

	// Enable processing of service topology aware hints
	EnableServiceTopology bool
}

// ConfigCell provides the [Config] and [ExternalConfig] configurations.
var ConfigCell = cell.Group(
	cell.Config(DefaultUserConfig),
	cell.Config(DeprecatedConfig{}),
	cell.Provide(
		// Bridge options from [option.DaemonConfig] to [loadbalancer.ExternalConfig] to avoid
		// direct dependency to DaemonConfig
		NewExternalConfig,

		// Validate and populate [loadbalancer.userConfig] to produce the final [loadbalancer.Config]
		NewConfig,
	),
)

// Config for load-balancing
// +deepequal-gen=true
type Config struct {
	UserConfig

	// NodePortMin is the minimum port address for the NodePort range
	NodePortMin uint16

	// NodePortMax is the maximum port address for the NodePort range
	NodePortMax uint16
}

func (c *Config) LoadBalancerUsesDSR() bool {
	return c.LBMode == LBModeDSR ||
		c.LBMode == LBModeHybrid ||
		c.LBModeAnnotation
}

type DeprecatedConfig struct {
	// NodePortAlg indicates which backend selection algorithm is used
	// ("random" or "maglev")
	NodePortAlg string `mapstructure:"node-port-algorithm"`

	// NodePortMode indicates in which mode NodePort implementation should run
	// ("snat", "dsr" or "hybrid")
	NodePortMode string `mapstructure:"node-port-mode"`
}

func (DeprecatedConfig) Flags(flags *pflag.FlagSet) {
	// Deprecated option for setting [LBAlgorithm]
	flags.String(NodePortAlgName, "", "BPF load balancing algorithm (\"random\", \"maglev\")")
	flags.MarkHidden(NodePortAlgName)
	flags.MarkDeprecated(NodePortAlgName, "Use --"+LBAlgorithmName+" instead")

	// Deprecated option for setting [LBMode]
	flags.String(NodePortModeName, "", "BPF NodePort mode (\"snat\", \"dsr\", \"hybrid\")")
	flags.MarkHidden(NodePortModeName)
	flags.MarkDeprecated(NodePortAlgName, "Use --"+LoadBalancerModeName+" instead")
}

func (def UserConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration("lb-retry-backoff-min", def.RetryBackoffMin, "Minimum amount of time to wait before retrying LB operation")
	flags.MarkHidden("lb-retry-backoff-min")

	flags.Duration("lb-retry-backoff-max", def.RetryBackoffMin, "Maximum amount of time to wait before retrying LB operation")
	flags.MarkHidden("lb-retry-backoff-max")

	flags.Int(LBMapEntriesName, def.LBMapEntries, "Maximum number of entries in Cilium BPF lbmap")

	flags.Int(LBServiceMapMaxEntries, def.LBServiceMapEntries, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for services (if this isn't set, the value of --%s will be used.)", LBMapEntriesName))
	flags.MarkHidden(LBServiceMapMaxEntries)

	flags.Int(LBBackendMapMaxEntries, def.LBBackendMapEntries, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for service backends (if this isn't set, the value of --%s will be used.)", LBMapEntriesName))
	flags.MarkHidden(LBBackendMapMaxEntries)

	flags.Int(LBRevNatMapMaxEntries, def.LBRevNatEntries, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for reverse NAT (if this isn't set, the value of --%s will be used.)", LBMapEntriesName))
	flags.MarkHidden(LBRevNatMapMaxEntries)

	flags.Int(LBAffinityMapMaxEntries, def.LBAffinityMapEntries, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for session affinities (if this isn't set, the value of --%s will be used.)", LBMapEntriesName))
	flags.MarkHidden(LBAffinityMapMaxEntries)

	flags.Int(LBSourceRangeMapMaxEntries, def.LBSourceRangeMapEntries, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for source ranges (if this isn't set, the value of --%s will be used.)", LBMapEntriesName))
	flags.MarkHidden(LBSourceRangeMapMaxEntries)

	flags.Bool(LBSourceRangeAllTypes, def.LBSourceRangeAllTypes, "Propagate loadbalancerSourceRanges to all corresponding service types")

	flags.Int(LBMaglevMapMaxEntries, def.LBMaglevMapEntries, fmt.Sprintf("Maximum number of entries in Cilium BPF lbmap for maglev (if this isn't set, the value of --%s will be used.)", LBMapEntriesName))
	flags.MarkHidden(LBMaglevMapMaxEntries)

	flags.Int(LBSockRevNatEntriesName, def.LBSockRevNatEntries, "Maximum number of entries for the SockRevNAT BPF map")

	flags.StringSlice(NodePortRange, []string{fmt.Sprintf("%d", NodePortMinDefault), fmt.Sprintf("%d", NodePortMaxDefault)}, "Set the min/max NodePort port range")

	flags.String(LBAlgorithmName, def.LBAlgorithm, "BPF load balancing algorithm (\"random\", \"maglev\")")

	flags.Bool(LoadBalancerModeAnnotationName, false, "Enable service-level annotation for configuring BPF load balancing mode")

	flags.String(LoadBalancerModeName, def.LBMode, "BPF load balancing mode (\"snat\", \"dsr\", \"hybrid\")")

	flags.String(LoadBalancerDSRDispatchName, def.DSRDispatch, "BPF load balancing DSR dispatch method (\"opt\", \"ipip\", \"geneve\")")

	flags.Bool(ExternalClusterIPName, def.ExternalClusterIP, "Enable external access to ClusterIP services (default false)")

	flags.Bool(AlgorithmAnnotationName, def.AlgorithmAnnotation, "Enable service-level annotation for configuring BPF load balancing algorithm")

	flags.Bool(EnableHealthCheckNodePortName, def.EnableHealthCheckNodePort, "Enables a healthcheck nodePort server for NodePort services with 'healthCheckNodePort' being set")

	flags.Duration("lb-pressure-metrics-interval", def.LBPressureMetricsInterval, "Interval for reporting pressure metrics for load-balancing BPF maps. 0 disables reporting.")
	flags.MarkHidden("lb-pressure-metrics-interval")

	flags.Bool(EnableServiceTopologyName, def.EnableServiceTopology, "Enable support for service topology aware hints")
}

// NewConfig takes the user-provided configuration, validates and processes it to produce the final
// configuration for load-balancing.
func NewConfig(log *slog.Logger, userConfig UserConfig, deprecatedConfig DeprecatedConfig, dcfg *option.DaemonConfig) (cfg Config, err error) {
	cfg.UserConfig = userConfig

	if cfg.LBMapEntries <= 0 {
		return Config{}, fmt.Errorf("specified LBMap max entries %d must be a value greater than 0", cfg.LBMapEntries)
	}

	if cfg.LBServiceMapEntries < 0 ||
		cfg.LBBackendMapEntries < 0 ||
		cfg.LBRevNatEntries < 0 ||
		cfg.LBAffinityMapEntries < 0 ||
		cfg.LBSourceRangeMapEntries < 0 ||
		cfg.LBMaglevMapEntries < 0 {
		return Config{}, fmt.Errorf("specified LB Service Map max entries must not be a negative value"+
			"(Service Map: %d, Service Backend: %d, Reverse NAT: %d, Session Affinity: %d, Source Range: %d, Maglev: %d)",
			cfg.LBServiceMapEntries,
			cfg.LBBackendMapEntries,
			cfg.LBRevNatEntries,
			cfg.LBAffinityMapEntries,
			cfg.LBSourceRangeMapEntries,
			cfg.LBMaglevMapEntries)
	}

	// Dynamically size the SockRevNat map if not set by the user.
	if cfg.LBSockRevNatEntries == 0 {
		getEntries := dcfg.GetDynamicSizeCalculator(log)
		cfg.LBSockRevNatEntries = getEntries(option.SockRevNATMapEntriesDefault, option.LimitTableAutoSockRevNatMin, option.LimitTableMax)
		log.Info(fmt.Sprintf("option %s set by dynamic sizing to %v", LBSockRevNatEntriesName, cfg.LBSockRevNatEntries)) // FIXME
	}

	if cfg.LBSockRevNatEntries < option.LimitTableMin {
		return Config{}, fmt.Errorf("specified Socket Reverse NAT table size %d must be greater or equal to %d",
			cfg.LBSockRevNatEntries, option.LimitTableMin)
	}
	if cfg.LBSockRevNatEntries > option.LimitTableMax {
		return Config{}, fmt.Errorf("specified Socket Reverse NAT tables size %d must not exceed maximum %d",
			cfg.LBSockRevNatEntries, option.LimitTableMax)
	}

	// Use [cfg.LBMapEntries] for map size if not overridden.
	opts := []*int{
		&cfg.LBServiceMapEntries,
		&cfg.LBBackendMapEntries,
		&cfg.LBRevNatEntries,
		&cfg.LBAffinityMapEntries,
		&cfg.LBSourceRangeMapEntries,
		&cfg.LBMaglevMapEntries,
	}
	for _, opt := range opts {
		if *opt == 0 {
			*opt = cfg.LBMapEntries
		}
	}

	cfg.NodePortMin = NodePortMinDefault
	cfg.NodePortMax = NodePortMaxDefault
	nodePortRange := cfg.NodePortRange
	// When passed via configmap, we might not get a slice but single
	// string instead, so split it if needed.
	if len(nodePortRange) == 1 {
		nodePortRange = strings.Split(nodePortRange[0], ",")
	}
	switch len(nodePortRange) {
	case 0:
		// Use the defaults
	case 2:
		min, err := strconv.ParseUint(nodePortRange[0], 10, 16)
		if err != nil {
			return Config{}, fmt.Errorf("Unable to parse min port value for NodePort range: %w", err)
		}
		cfg.NodePortMin = uint16(min)
		max, err := strconv.ParseUint(nodePortRange[1], 10, 16)
		if err != nil {
			return Config{}, fmt.Errorf("Unable to parse max port value for NodePort range: %w", err)
		}
		cfg.NodePortMax = uint16(max)
		if cfg.NodePortMax <= cfg.NodePortMin {
			return Config{}, errors.New("NodePort range min port must be smaller than max port")
		}
	default:
		return Config{}, fmt.Errorf("Unable to parse min/max port value for NodePort range: %s", NodePortRange)
	}

	if deprecatedConfig.NodePortAlg != "" {
		cfg.LBAlgorithm = deprecatedConfig.NodePortAlg
	}

	if cfg.LBAlgorithm != LBAlgorithmRandom &&
		cfg.LBAlgorithm != LBAlgorithmMaglev {
		return Config{}, fmt.Errorf("Invalid value for --%s: %s", LBAlgorithmName, cfg.LBAlgorithm)
	}

	if deprecatedConfig.NodePortMode != "" {
		if cfg.LBMode != DefaultUserConfig.LBMode {
			return Config{}, fmt.Errorf("both --%s and --%s were set. Use --%s instead.",
				LoadBalancerModeName, NodePortModeName, LoadBalancerModeName)
		}
		cfg.LBMode = deprecatedConfig.NodePortMode
	}

	if cfg.LBMode != LBModeSNAT && cfg.LBMode != LBModeDSR && cfg.LBMode != LBModeHybrid {
		return Config{}, fmt.Errorf("Invalid value for --%s: %s", LoadBalancerModeName, cfg.LBMode)
	}

	if cfg.LBModeAnnotation &&
		cfg.LBMode == LBModeHybrid {
		return Config{}, fmt.Errorf("The value --%s=%s is not supported as default under annotation mode", LoadBalancerModeName, cfg.LBMode)
	}

	/* FIXME:

	if cfg.NodePortMode == option.NodePortModeDSR &&
		cfg.LoadBalancerDSRDispatch != option.DSRDispatchOption &&
		cfg.LoadBalancerDSRDispatch != option.DSRDispatchIPIP &&
		cfg.LoadBalancerDSRDispatch != option.DSRDispatchGeneve {
		return fmt.Errorf("Invalid value for --%s: %s", option.LoadBalancerDSRDispatch, cfg.LoadBalancerDSRDispatch)
	}

	if cfg.NodePortMode == option.NodePortModeHybrid &&
		cfg.LoadBalancerDSRDispatch != option.DSRDispatchOption &&
		cfg.LoadBalancerDSRDispatch != option.DSRDispatchGeneve {
		return fmt.Errorf("Invalid value for --%s: %s", option.LoadBalancerDSRDispatch, cfg.LoadBalancerDSRDispatch)
	}

	if cfg.LoadBalancerModeAnnotation &&
		cfg.LoadBalancerDSRDispatch != option.DSRDispatchIPIP {
		return fmt.Errorf("Invalid value for --%s: %s", option.LoadBalancerDSRDispatch, cfg.LoadBalancerDSRDispatch)
	}*/

	return
}

var DefaultUserConfig = UserConfig{
	RetryBackoffMin:           50 * time.Millisecond,
	RetryBackoffMax:           time.Minute,
	LBMapEntries:              DefaultLBMapMaxEntries,
	LBPressureMetricsInterval: 5 * time.Minute,

	LBServiceMapEntries:     0, // Uses [LBMapEntries] if zero
	LBBackendMapEntries:     0, // ...
	LBRevNatEntries:         0, // ...
	LBAffinityMapEntries:    0, // ...
	LBSourceRangeMapEntries: 0, // ...
	LBMaglevMapEntries:      0, // ...

	LBSockRevNatEntries: 0, // Probes for suitable size if zero

	LBSourceRangeAllTypes: false,

	NodePortRange: []string{},
	LBAlgorithm:   LBAlgorithmRandom,

	LBMode: LBModeSNAT,

	DSRDispatch: DSRDispatchOption,

	// Defaults to false to retain prior behaviour to not route external packets
	// to ClusterIP services.
	ExternalClusterIP: false,

	AlgorithmAnnotation: false,

	EnableHealthCheckNodePort: true,

	EnableServiceTopology: false,
}

var DefaultConfig = Config{
	UserConfig:  DefaultUserConfig,
	NodePortMin: NodePortMinDefault,
	NodePortMax: NodePortMaxDefault,
}

// TestConfig are the configuration options for testing. Only provided by tests and not present in the agent.
type TestConfig struct {
	TestFaultProbability float32 `mapstructure:"lb-test-fault-probability"`
}

func (def TestConfig) Flags(flags *pflag.FlagSet) {
	flags.Float32("lb-test-fault-probability", def.TestFaultProbability, "Probability for fault injection in LBMaps (0..1)")
}

// ExternalConfig are configuration options derived from external sources such as
// DaemonConfig. This avoids direct access of larger configuration structs.
type ExternalConfig struct {
	ZoneMapper

	EnableIPv4, EnableIPv6                 bool
	KubeProxyReplacement                   bool
	NodePortMin, NodePortMax               uint16
	NodePortAlg                            string
	LoadBalancerAlgorithmAnnotation        bool
	BPFSocketLBHostnsOnly                  bool
	EnableSocketLB                         bool
	EnableSocketLBPodConnectionTermination bool
	EnableHealthCheckLoadBalancerIP        bool

	// The following options will be removed in v1.19
	EnableHostPort              bool
	EnableSessionAffinity       bool
	EnableSVCSourceRangeCheck   bool
	EnableInternalTrafficPolicy bool
}

// NewExternalConfig maps the daemon config to [ExternalConfig].
func NewExternalConfig(cfg *option.DaemonConfig, kprCfg kpr.KPRConfig) ExternalConfig {
	return ExternalConfig{
		ZoneMapper:                             cfg,
		EnableIPv4:                             cfg.EnableIPv4,
		EnableIPv6:                             cfg.EnableIPv6,
		KubeProxyReplacement:                   kprCfg.KubeProxyReplacement == option.KubeProxyReplacementTrue || kprCfg.EnableNodePort,
		BPFSocketLBHostnsOnly:                  cfg.BPFSocketLBHostnsOnly,
		EnableSocketLB:                         kprCfg.EnableSocketLB,
		EnableSocketLBPodConnectionTermination: cfg.EnableSocketLBPodConnectionTermination,
		EnableHealthCheckLoadBalancerIP:        cfg.EnableHealthCheckLoadBalancerIP,
		EnableHostPort:                         kprCfg.EnableHostPort,
		EnableSessionAffinity:                  kprCfg.EnableSessionAffinity,
		EnableSVCSourceRangeCheck:              kprCfg.EnableSVCSourceRangeCheck,
		EnableInternalTrafficPolicy:            cfg.EnableInternalTrafficPolicy,
	}
}

type ZoneMapper interface {
	GetZoneID(string) uint8
}

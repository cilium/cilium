// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"fmt"
	"log/slog"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

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
)

type Config struct {
	EnableExperimentalLB bool          `mapstructure:"enable-experimental-lb"`
	RetryBackoffMin      time.Duration `mapstructure:"lb-retry-backoff-min"`
	RetryBackoffMax      time.Duration `mapstructure:"lb-retry-backoff-max"`

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
}

const (
	// DefaultLBMapMaxEntries is the default size for the load-balancing BPF maps.
	DefaultLBMapMaxEntries = 65536
)

// UserConfig is the configuration provided by the user that has not been processed.
type UserConfig Config

func (def UserConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-experimental-lb", def.EnableExperimentalLB, "Enable experimental load-balancing control-plane")
	flags.MarkHidden("enable-experimental-lb")

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

}

// NewConfig takes the user-provided configuration, validates and processes it to produce the final
// configuration for load-balancing.
func NewConfig(log *slog.Logger, userConfig UserConfig, dcfg *option.DaemonConfig) (cfg Config, err error) {
	cfg = Config(userConfig)

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
		getEntries := dcfg.GetDynamicSizeCalculator()
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
	return
}

var DefaultConfig = UserConfig{
	EnableExperimentalLB: true,
	RetryBackoffMin:      50 * time.Millisecond,
	RetryBackoffMax:      time.Minute,
	LBMapEntries:         DefaultLBMapMaxEntries,

	LBServiceMapEntries:     0, // Uses [LBMapEntries] if zero
	LBBackendMapEntries:     0, // ...
	LBRevNatEntries:         0, // ...
	LBAffinityMapEntries:    0, // ...
	LBSourceRangeMapEntries: 0, // ...
	LBMaglevMapEntries:      0, // ...

	LBSockRevNatEntries: 0, // Probes for suitable size if zero

	LBSourceRangeAllTypes: false,
}

// TestConfig are the configuration options for testing. Only provided by tests and not present in the agent.
type TestConfig struct {
	TestFaultProbability float32 `mapstructure:"lb-test-fault-probability"`

	// NodePortAlg mirrors option.Config.NodePortAlg. This can be removed when the NodePort config
	// flags move away from option.DaemonConfig and can thus be set directly.
	NodePortAlg string `mapstructure:"node-port-algorithm"`

	// EnableHealthCheckNodePort is defined here to allow script tests to enable this.
	// Can be removed once this option moves out from DaemonConfig into [Config].
	EnableHealthCheckNodePort bool `mapstructure:"enable-health-check-nodeport"`

	// LoadBalancerAlgorithmAnnotation mirrors option.Config.LoadBalancerAlgorithmAnnotation.
	LoadBalancerAlgorithmAnnotation bool `mapstructure:"bpf-lb-algorithm-annotation"`

	// ExternalClusterIP mirrors option.Config.ExternalClusterIP
	ExternalClusterIP bool `mapstructure:"bpf-lb-external-clusterip"`
}

func (def TestConfig) Flags(flags *pflag.FlagSet) {
	flags.Float32("lb-test-fault-probability", def.TestFaultProbability, "Probability for fault injection in LBMaps")
	flags.String("node-port-algorithm", option.NodePortAlgRandom, "NodePort algorithm")
	flags.Bool("enable-health-check-nodeport", false, "Enable the NodePort health check server")
	flags.Bool("bpf-lb-algorithm-annotation", false, "Enable service-level annotation for configuring BPF load balancing algorithm")
	flags.Bool(option.ExternalClusterIPName, false, "Enable cluster-external access to ClusterIPs")
}

// ExternalConfig are configuration options derived from external sources such as
// DaemonConfig. This avoids direct access of larger configuration structs.
type ExternalConfig struct {
	ZoneMapper

	EnableIPv4, EnableIPv6          bool
	ExternalClusterIP               bool
	EnableHealthCheckNodePort       bool
	KubeProxyReplacement            bool
	NodePortMin, NodePortMax        uint16
	NodePortAlg                     string
	LoadBalancerAlgorithmAnnotation bool
}

// NewExternalConfig maps the daemon config to [ExternalConfig].
func NewExternalConfig(cfg *option.DaemonConfig) ExternalConfig {
	return ExternalConfig{
		ZoneMapper:                      cfg,
		EnableIPv4:                      cfg.EnableIPv4,
		EnableIPv6:                      cfg.EnableIPv6,
		ExternalClusterIP:               cfg.ExternalClusterIP,
		KubeProxyReplacement:            cfg.KubeProxyReplacement == option.KubeProxyReplacementTrue || cfg.EnableNodePort,
		EnableHealthCheckNodePort:       cfg.EnableHealthCheckNodePort,
		NodePortMin:                     uint16(cfg.NodePortMin),
		NodePortMax:                     uint16(cfg.NodePortMax),
		NodePortAlg:                     cfg.NodePortAlg,
		LoadBalancerAlgorithmAnnotation: cfg.LoadBalancerAlgorithmAnnotation,
	}
}

type ZoneMapper interface {
	GetZoneID(string) uint8
}

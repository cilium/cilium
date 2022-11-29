package config

import (
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/spf13/pflag"
)

type ServiceConfig struct {
	// options used in service.go that aren't too generic:

	// EnableHealthCheckNodePort enables health checking of NodePort by
	// cilium
	EnableHealthCheckNodePort bool

	// EnableSVCSourceRangeCheck enables check of loadBalancerSourceRanges
	EnableSVCSourceRangeCheck bool

	// EnableSessionAffinity enables a support for service sessionAffinity
	EnableSessionAffinity bool

	EnableServiceTopology bool

	// ExternalClusterIP enables routing to ClusterIP services from outside
	// the cluster. This mirrors the behaviour of kube-proxy.
	ExternalClusterIP bool `mapstructure:"bpf-lb-external-clusterip"`

	// NodePortAlg indicates which backend selection algorithm is used
	// ("random" or "maglev")
	NodePortAlg string `mapstructure:"node-port-algorithm"`

	//NodePortNat46X64 bool // doesn't have a flag, left it in option.Config.

	// options that were too generic:
	// EnableIPv4, EnableIPv6
	// DatapathMode
	//
	// other service related options not added yet:
	// Maglev*, LBMap*
	//
}

const (
	// NodePortAlgRandom is for randomly selecting a backend
	NodePortAlgRandom = "random"

	// NodePortAlgMaglev is for using maglev consistent hashing for backend selection
	NodePortAlgMaglev = "maglev"
)

// Option names
const (
	EnableHealthCheckNodePort = "enable-health-check-nodeport"

	EnableSVCSourceRangeCheck = "enable-svc-source-range-check"

	NodePortAlg = "node-port-algorithm"

	EnableSessionAffinity = "enable-session-affinity"

	EnableServiceTopology = "enable-service-topology"
	ExternalClusterIP     = "bpf-lb-external-clusterip"
)

func (def ServiceConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableHealthCheckNodePort, def.EnableHealthCheckNodePort,
		"Enables a healthcheck server for NodePort services with 'healthCheckNodePort' being set")

	flags.Bool(EnableSVCSourceRangeCheck, def.EnableSVCSourceRangeCheck,
		"Enable check of service source ranges (currently, only for LoadBalancer)")

	flags.Bool(EnableSessionAffinity, def.EnableSessionAffinity,
		"Enable support for service session affinity")

	flags.Bool(EnableServiceTopology, def.EnableServiceTopology,
		"Enable support for service topology aware hints")

	flags.Bool(ExternalClusterIP, def.ExternalClusterIP,
		"Enable external access to ClusterIP services (default false)")

	flags.String(NodePortAlg, def.NodePortAlg,
		"BPF load balancing algorithm (\"random\", \"maglev\")")
	flags.MarkHidden("node-port-algorithm")
}

var defaultConfig = ServiceConfig{
	// FIXME move definitions from pkg/defaults to here.
	EnableHealthCheckNodePort: defaults.EnableHealthCheckNodePort,
	EnableSVCSourceRangeCheck: true,
	EnableSessionAffinity:     false,
	EnableServiceTopology:     false,
	ExternalClusterIP:         defaults.ExternalClusterIP,
	NodePortAlg:               NodePortAlgRandom,
}

var Cell = cell.Config(defaultConfig)

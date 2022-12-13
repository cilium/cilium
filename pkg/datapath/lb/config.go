package lb

import (
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/spf13/pflag"
)

// TODO: Should probably live in its own package to avoid cycles.
// e.g. pkg/datapath/lb/config, or could even just stick all datapath
// configs into pkg/datapath/config?

type Config struct {
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

	// Maglev backend table size (M) per service. Must be prime number.
	MaglevTableSize uint `mapstructure:"bpf-lb-maglev-table-size"`

	// MaglevHashSeed contains the cluster-wide seed for the hash(es).
	MaglevHashSeed string `mapstructure:"bpf-lb-maglev-hash-seed"`

	// options that were too generic:
	// EnableIPv4, EnableIPv6
	// DatapathMode
	//
	// other service related options not added yet:
	// LBMap*
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

	MaglevTableSize = "bpf-lb-maglev-table-size"
	MaglevHashSeed  = "bpf-lb-maglev-hash-seed"
)

func (def Config) Flags(flags *pflag.FlagSet) {
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

	flags.Uint(MaglevTableSize, def.MaglevTableSize, "Maglev per service backend table size (parameter M)")

	flags.String(MaglevHashSeed, def.MaglevHashSeed, "Maglev cluster-wide hash seed (base64 encoded)")
}

var DefaultConfig = Config{
	// FIXME move definitions from pkg/defaults to here.
	EnableHealthCheckNodePort: defaults.EnableHealthCheckNodePort,
	EnableSVCSourceRangeCheck: true,
	EnableSessionAffinity:     false,
	EnableServiceTopology:     false,
	ExternalClusterIP:         defaults.ExternalClusterIP,
	NodePortAlg:               NodePortAlgRandom,
	MaglevTableSize:           maglev.DefaultTableSize,
	MaglevHashSeed:            maglev.DefaultHashSeed,
}

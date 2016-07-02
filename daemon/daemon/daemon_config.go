package daemon

import (
	"net"

	"github.com/noironetworks/cilium-net/bpf/lxcmap"
	"github.com/noironetworks/cilium-net/common/types"

	consulAPI "github.com/hashicorp/consul/api"
)

const (
	OptionPolicyTracing = "PolicyTracing"
)

var (
	OptionSpecPolicyTracing = types.Option{
		Description: "Enable tracing when resolving policy (Debug)",
	}

	DaemonOptionLibrary = types.OptionLibrary{
		types.OptionNAT46:               &types.OptionSpecNAT46,
		types.OptionDropNotify:          &types.OptionSpecDropNotify,
		types.OptionDebug:               &types.OptionSpecDebug,
		types.OptionPolicy:              &types.OptionSpecPolicy,
		types.OptionConntrack:           &types.OptionSpecConntrack,
		types.OptionConntrackAccounting: &types.OptionSpecConntrackAccounting,
		OptionPolicyTracing:             &OptionSpecPolicyTracing,
	}
)

// Config is the configuration used by Daemon.
type Config struct {
	LibDir             string                // Cilium library directory
	RunDir             string                // Cilium runtime directory
	LXCMap             *lxcmap.LXCMap        // LXCMap where all LXCs are stored
	NodeAddress        net.IP                // Node IPv6 Address
	IPv4Range          *net.IPNet            // Containers IPv4 Address range
	IPv4Prefix         string                // IPv4 prefix
	Device             string                // Receive device
	ConsulConfig       *consulAPI.Config     // Consul configuration
	DockerEndpoint     string                // Docker endpoint
	K8sEndpoint        string                // Kubernetes endpoint
	ValidLabelPrefixes *types.LabelPrefixCfg // Label prefixes used to filter from all labels
	UIServerAddr       string                // TCP address for UI server
	Tunnel             string                // Tunnel mode

	RestoreState bool // RestoreState restores the state from previous running daemons.

	// Options changeable at runtime
	Opts *types.BoolOptions
}

func NewConfig() *Config {
	return &Config{
		Opts: types.NewBoolOptions(&DaemonOptionLibrary),
	}
}

func (c *Config) IsUIEnabled() bool {
	return c.UIServerAddr != ""
}

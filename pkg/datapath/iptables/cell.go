// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"iptables",
	"Handle iptables-related configuration for Cilium",

	// Manage "cilium_node_set_v4" and "cilium_node_set_v6" kernel IP sets to
	// collect IPv4 and IPv6 node addresses (respectively) and exclude traffic to
	// those IPs from being masqueraded.
	ipset.Cell,

	cell.Config(defaultConfig),
	cell.ProvidePrivate(func(
		cfg *option.DaemonConfig,
	) SharedConfig {
		return SharedConfig{
			TunnelingEnabled:                cfg.TunnelingEnabled(),
			NodeIpsetNeeded:                 cfg.NodeIpsetNeeded(),
			IptablesMasqueradingIPv4Enabled: cfg.IptablesMasqueradingIPv4Enabled(),
			IptablesMasqueradingIPv6Enabled: cfg.IptablesMasqueradingIPv6Enabled(),

			EnableIPv4:                  cfg.EnableIPv4,
			EnableIPv6:                  cfg.EnableIPv6,
			EnableXTSocketFallback:      cfg.EnableXTSocketFallback,
			EnableBPFTProxy:             cfg.EnableBPFTProxy,
			InstallNoConntrackIptRules:  cfg.InstallNoConntrackIptRules,
			EnableEndpointRoutes:        cfg.EnableEndpointRoutes,
			IPAM:                        cfg.IPAM,
			EnableIPSec:                 cfg.EnableIPSec,
			MasqueradeInterfaces:        cfg.MasqueradeInterfaces,
			EnableMasqueradeRouteSource: cfg.EnableMasqueradeRouteSource,
			EnableL7Proxy:               cfg.EnableL7Proxy,
			InstallIptRules:             cfg.InstallIptRules,
		}
	}),
	cell.Provide(newIptablesManager),
)

type Config struct {
	// IPTablesLockTimeout defines the "-w" iptables option when the
	// iptables CLI is directly invoked from the Cilium agent.
	IPTablesLockTimeout time.Duration

	// DisableIptablesFeederRules specifies which chains will be excluded
	// when installing the feeder rules
	DisableIptablesFeederRules []string

	// IPTablesRandomFully defines the "--random-fully" iptables option when the
	// iptables CLI is directly invoked from the Cilium agent.
	IPTablesRandomFully bool

	// PrependIptablesChains, when enabled, prepends custom iptables chains instead of appending.
	PrependIptablesChains bool
}

var defaultConfig = Config{
	IPTablesLockTimeout:        5 * time.Second,
	PrependIptablesChains:      true,
	DisableIptablesFeederRules: []string{},
	IPTablesRandomFully:        false,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("iptables-lock-timeout", def.IPTablesLockTimeout, "Time to pass to each iptables invocation to wait for xtables lock acquisition")
	flags.StringSlice("disable-iptables-feeder-rules", def.DisableIptablesFeederRules, "Chains to ignore when installing feeder rules.")
	flags.Bool("iptables-random-fully", def.IPTablesRandomFully, "Set iptables flag random-fully on masquerading rules")
	flags.Bool("prepend-iptables-chains", def.PrependIptablesChains, "Prepend custom iptables chains instead of appending")
}

type SharedConfig struct {
	TunnelingEnabled                bool
	NodeIpsetNeeded                 bool
	IptablesMasqueradingIPv4Enabled bool
	IptablesMasqueradingIPv6Enabled bool

	EnableIPv4                  bool
	EnableIPv6                  bool
	EnableXTSocketFallback      bool
	EnableBPFTProxy             bool
	InstallNoConntrackIptRules  bool
	EnableEndpointRoutes        bool
	IPAM                        string
	EnableIPSec                 bool
	MasqueradeInterfaces        []string
	EnableMasqueradeRouteSource bool
	EnableL7Proxy               bool
	InstallIptRules             bool
}

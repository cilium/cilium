// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	ipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
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
		tunnelCfg tunnel.Config,
		ipsecCfg ipsec.Config,
		wgConfig wgTypes.Config,
		lbConfig lb.Config,
	) SharedConfig {
		return SharedConfig{
			TunnelingEnabled:                cfg.TunnelingEnabled(),
			TunnelPort:                      tunnelCfg.Port(),
			NodeIpsetNeeded:                 cfg.NodeIpsetNeeded(),
			IptablesMasqueradingIPv4Enabled: cfg.IptablesMasqueradingIPv4Enabled(),
			IptablesMasqueradingIPv6Enabled: cfg.IptablesMasqueradingIPv6Enabled(),

			EnableIPv4:                  cfg.EnableIPv4,
			EnableIPv6:                  cfg.EnableIPv6,
			EnableBPFTProxy:             cfg.EnableBPFTProxy,
			InstallNoConntrackIptRules:  cfg.InstallNoConntrackIptRules,
			EnableEndpointRoutes:        cfg.EnableEndpointRoutes,
			IPAM:                        cfg.IPAM,
			EnableIPSec:                 ipsecCfg.Enabled(),
			MasqueradeInterfaces:        cfg.MasqueradeInterfaces,
			EnableMasqueradeRouteSource: cfg.EnableMasqueradeRouteSource,
			EnableL7Proxy:               cfg.EnableL7Proxy,
			InstallIptRules:             cfg.InstallIptRules,
			EnableWireguard:             wgConfig.Enabled(),
			NATExcludedPorts:            buildIptablesNATExcludedPorts(tunnelCfg, wgConfig),
			NATMinSNATPort:              lbConfig.NodePortMax + 1,
		}
	}),
	cell.Provide(newManager),
)

// buildIptablesNATExcludedPorts returns the sorted list of UDP ports owned by
// Cilium kernel sockets that must not be selected as SNAT source ports by
// iptables MASQUERADE rules. These ports are injected into split --to-ports
// ranges so the kernel's NAT never picks them.
func buildIptablesNATExcludedPorts(tunnelCfg tunnel.Config, wgConfig wgTypes.Config) []uint16 {
	var ports []uint16

	if tunnelCfg.Port() != 0 {
		ports = append(ports, tunnelCfg.Port())
	}

	if wgConfig.Enabled() {
		ports = append(ports, wgTypes.ListenPort)
	}

	// Keep sorted for deterministic rule generation.
	slices.Sort(ports)

	return ports
}

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

	// EnableXTSocketFallback allows disabling of kernel's ip_early_demux
	// sysctl option if `xt_socket` kernel module is not available.
	EnableXTSocketFallback bool
}

var defaultConfig = Config{
	IPTablesLockTimeout:        5 * time.Second,
	PrependIptablesChains:      true,
	DisableIptablesFeederRules: []string{},
	IPTablesRandomFully:        false,
	EnableXTSocketFallback:     true,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("iptables-lock-timeout", def.IPTablesLockTimeout, "Time to pass to each iptables invocation to wait for xtables lock acquisition")
	flags.StringSlice("disable-iptables-feeder-rules", def.DisableIptablesFeederRules, "Chains to ignore when installing feeder rules.")
	flags.Bool("iptables-random-fully", def.IPTablesRandomFully, "Set iptables flag random-fully on masquerading rules")
	flags.Bool("prepend-iptables-chains", def.PrependIptablesChains, "Prepend custom iptables chains instead of appending")
	flags.Bool("enable-xt-socket-fallback", def.EnableXTSocketFallback, "Enable fallback for missing xt_socket module")
}

type SharedConfig struct {
	TunnelingEnabled                bool
	TunnelPort                      uint16
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
	EnableWireguard             bool

	// NATExcludedPorts is the sorted list of UDP ports owned by Cilium kernel
	// sockets (VXLAN, Geneve, WireGuard) that must not be used
	// as SNAT source ports in iptables MASQUERADE rules.
	NATExcludedPorts []uint16

	// NATMinSNATPort is the lower bound of the port range used for MASQUERADE
	// --to-ports. Mirrors the BPF SNAT range: NodePortMax+1 (typically 32768).
	NATMinSNATPort uint16
}

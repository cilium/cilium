// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"iptables",
	"Handle iptables-related configuration for Cilium",

	cell.Config(defaultConfig),
	cell.ProvidePrivate(func(
		cfg *option.DaemonConfig,
	) SharedConfig {
		return SharedConfig{
			EnableIPv4:             cfg.EnableIPv4,
			EnableIPv6:             cfg.EnableIPv6,
			RoutingMode:            cfg.RoutingMode,
			EnableXTSocketFallback: cfg.EnableXTSocketFallback,
			EnableBPFTProxy:        cfg.EnableBPFTProxy,
		}
	}),
	cell.Provide(newIptablesManager),
)

type Config struct {
	// IPTablesLockTimeout defines the "-w" iptables option when the
	// iptables CLI is directly invoked from the Cilium agent.
	IPTablesLockTimeout time.Duration
}

var defaultConfig = Config{
	IPTablesLockTimeout: 5 * time.Second,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("iptables-lock-timeout", def.IPTablesLockTimeout, "Time to pass to each iptables invocation to wait for xtables lock acquisition")
}

type SharedConfig struct {
	EnableIPv4             bool
	EnableIPv6             bool
	RoutingMode            string
	EnableXTSocketFallback bool
	EnableBPFTProxy        bool
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kpr

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"kube-proxy-replacement",
	"Provides KPR config",

	cell.Config(defaultFlags),
	cell.Provide(NewKPRConfig),
)

type KPRFlags struct {
	KubeProxyReplacement bool
	EnableSocketLB       bool `mapstructure:"bpf-lb-sock"`
	EnableNodePort       bool
}

var defaultFlags = KPRFlags{
	KubeProxyReplacement: false,
	EnableSocketLB:       false,
	EnableNodePort:       false,
}

func (def KPRFlags) Flags(flags *pflag.FlagSet) {
	flags.Bool("kube-proxy-replacement", def.KubeProxyReplacement, "Enable kube-proxy replacement")

	flags.Bool("bpf-lb-sock", def.EnableSocketLB, "Enable socket-based LB for E/W traffic")

	flags.Bool("enable-node-port", def.EnableNodePort, "Enable NodePort type services by Cilium")
	flags.MarkDeprecated("enable-node-port", "The flag will be removed in v1.19. The feature will be unconditionally enabled by enabling kube-proxy-replacement")
}

type KPRConfig struct {
	KubeProxyReplacement bool
	EnableNodePort       bool
	EnableSocketLB       bool
}

func NewKPRConfig(flags KPRFlags) (KPRConfig, error) {
	cfg := KPRConfig{
		KubeProxyReplacement: flags.KubeProxyReplacement,
		EnableNodePort:       flags.EnableNodePort,
		EnableSocketLB:       flags.EnableSocketLB,
	}

	if flags.KubeProxyReplacement {
		cfg.EnableNodePort = true
		cfg.EnableSocketLB = true
	}

	return cfg, nil
}

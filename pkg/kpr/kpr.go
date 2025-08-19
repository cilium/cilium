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
	EnableExternalIPs    bool
	EnableHostPort       bool
}

var defaultFlags = KPRFlags{
	KubeProxyReplacement: false,
	EnableSocketLB:       false,
	EnableNodePort:       false,
	EnableExternalIPs:    false,
	EnableHostPort:       false,
}

func (def KPRFlags) Flags(flags *pflag.FlagSet) {
	flags.Bool("kube-proxy-replacement", def.KubeProxyReplacement, "Enable kube-proxy replacement")

	flags.Bool("bpf-lb-sock", def.EnableSocketLB, "Enable socket-based LB for E/W traffic")

	flags.Bool("enable-node-port", def.EnableNodePort, "Enable NodePort type services by Cilium")
	flags.MarkDeprecated("enable-node-port", "The flag will be removed in v1.19. The feature will be unconditionally enabled by enabling kube-proxy-replacement")

	flags.Bool("enable-external-ips", def.EnableExternalIPs, "Enable k8s service externalIPs feature (requires enabling enable-node-port)")
	flags.MarkDeprecated("enable-external-ips", "The flag will be removed in v1.19. The feature will be unconditionally enabled by enabling kube-proxy-replacement")

	flags.Bool("enable-host-port", def.EnableHostPort, "Enable k8s hostPort mapping feature (requires enabling enable-node-port)")
	flags.MarkDeprecated("enable-host-port", "The flag will be removed in v1.19. The feature will be unconditionally enabled by enabling kube-proxy-replacement")
}

type KPRConfig struct {
	KubeProxyReplacement bool
	EnableNodePort       bool
	EnableExternalIPs    bool
	EnableHostPort       bool
	EnableSocketLB       bool
}

func NewKPRConfig(flags KPRFlags) (KPRConfig, error) {
	cfg := KPRConfig{
		KubeProxyReplacement: flags.KubeProxyReplacement,
		EnableNodePort:       flags.EnableNodePort,
		EnableExternalIPs:    flags.EnableExternalIPs,
		EnableHostPort:       flags.EnableHostPort,
		EnableSocketLB:       flags.EnableSocketLB,
	}

	if flags.KubeProxyReplacement {
		cfg.EnableNodePort = true
		cfg.EnableExternalIPs = true
		cfg.EnableHostPort = true
		cfg.EnableSocketLB = true
	}

	if !cfg.EnableNodePort {
		// Disable features depending on NodePort
		cfg.EnableHostPort = false
		cfg.EnableExternalIPs = false
	}

	return cfg, nil
}

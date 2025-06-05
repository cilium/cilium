// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kpr

import (
	"fmt"

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
	KubeProxyReplacement      string
	EnableSocketLB            bool `mapstructure:"bpf-lb-sock"`
	EnableNodePort            bool
	EnableExternalIPs         bool
	EnableHostPort            bool
	EnableSVCSourceRangeCheck bool
	EnableSessionAffinity     bool
}

var defaultFlags = KPRFlags{
	KubeProxyReplacement:      "false",
	EnableSocketLB:            false,
	EnableNodePort:            false,
	EnableExternalIPs:         false,
	EnableHostPort:            false,
	EnableSVCSourceRangeCheck: true,
	EnableSessionAffinity:     true,
}

func (def KPRFlags) Flags(flags *pflag.FlagSet) {
	flags.String("kube-proxy-replacement", def.KubeProxyReplacement, "Enable kube-proxy replacement")

	flags.Bool("bpf-lb-sock", def.EnableSocketLB, "Enable socket-based LB for E/W traffic")

	flags.Bool("enable-node-port", def.EnableNodePort, "Enable NodePort type services by Cilium")
	flags.MarkDeprecated("enable-node-port", "The flag will be removed in v1.19. The feature will be unconditionally enabled by enabling kube-proxy-replacement")

	flags.Bool("enable-external-ips", def.EnableExternalIPs, "Enable k8s service externalIPs feature (requires enabling enable-node-port)")
	flags.MarkDeprecated("enable-external-ips", "The flag will be removed in v1.19. The feature will be unconditionally enabled by enabling kube-proxy-replacement")

	flags.Bool("enable-host-port", def.EnableHostPort, "Enable k8s hostPort mapping feature (requires enabling enable-node-port)")
	flags.MarkDeprecated("enable-host-port", "The flag will be removed in v1.19. The feature will be unconditionally enabled by enabling kube-proxy-replacement")

	flags.Bool("enable-svc-source-range-check", def.EnableSVCSourceRangeCheck, "Enable check of service source ranges (currently, only for LoadBalancer)")
	flags.MarkDeprecated("enable-svc-source-range-check", "The flag will be removed in v1.19. The feature will be unconditionally enabled by enabling kube-proxy-replacement")

	flags.Bool("enable-session-affinity", def.EnableSessionAffinity, "Enable support for service session affinity")
	flags.MarkDeprecated("enable-session-affinity", "The flag to control Session Affinity has been deprecated, and it will be removed in v1.19. The feature will be unconditionally enabled.")

}

type KPRConfig struct {
	KubeProxyReplacement      string
	EnableNodePort            bool
	EnableExternalIPs         bool
	EnableHostPort            bool
	EnableSVCSourceRangeCheck bool
	EnableSessionAffinity     bool
	EnableSocketLB            bool
}

func NewKPRConfig(flags KPRFlags) (KPRConfig, error) {
	if flags.KubeProxyReplacement != "true" && flags.KubeProxyReplacement != "false" {
		return KPRConfig{}, fmt.Errorf("invalid value for kube-proxy-replacement")
	}

	cfg := KPRConfig{
		KubeProxyReplacement:      flags.KubeProxyReplacement,
		EnableNodePort:            flags.EnableNodePort,
		EnableExternalIPs:         flags.EnableExternalIPs,
		EnableHostPort:            flags.EnableHostPort,
		EnableSVCSourceRangeCheck: flags.EnableSVCSourceRangeCheck,
		EnableSessionAffinity:     flags.EnableSessionAffinity,
		EnableSocketLB:            flags.EnableSocketLB,
	}

	if flags.KubeProxyReplacement == "true" {
		cfg.EnableNodePort = true
		cfg.EnableExternalIPs = true
		cfg.EnableHostPort = true
		cfg.EnableSessionAffinity = true
		cfg.EnableSocketLB = true
	}

	if !cfg.EnableNodePort {
		// Disable features depending on NodePort
		cfg.EnableHostPort = false
		cfg.EnableExternalIPs = false
		cfg.EnableSVCSourceRangeCheck = false
	}

	return cfg, nil
}

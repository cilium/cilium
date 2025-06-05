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

	cell.Config(defaultConfig),
	cell.Provide(NewKPROpts),
)

type KPRConfig struct {
	KubeProxyReplacement string
	EnableNodePort       bool
}

var defaultConfig = KPRConfig{
	KubeProxyReplacement: "false",
	EnableNodePort:       false,
}

func (def KPRConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-node-port", def.EnableNodePort, "Enable NodePort type services by Cilium")
	flags.MarkDeprecated("enable-node-port", "The flag will be removed in v1.19. The feature will be unconditionally enabled by enabling kube-proxy-replacement")

	flags.String("kube-proxy-replacement", def.KubeProxyReplacement, "Enable kube-proxy replacement")
}

type KPROpts struct {
	KubeProxyReplacement string
	EnableNodePort       bool
}

func NewKPROpts(cfg KPRConfig) KPROpts {
	opts := KPROpts{
		KubeProxyReplacement: cfg.KubeProxyReplacement,
		EnableNodePort:       cfg.EnableNodePort,
	}

	if cfg.KubeProxyReplacement == "true" {
		opts.EnableNodePort = true
	}

	return opts
}

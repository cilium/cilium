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
	KubeProxyReplacement                   bool
	EnableSocketLB                         bool `mapstructure:"bpf-lb-sock"`
	EnableSocketLBHostnsOnly               bool `mapstructure:"bpf-lb-sock-hostns-only"`
	EnableSocketLBPodConnectionTermination bool `mapstructure:"bpf-lb-sock-pod-connection-termination"`
}

var defaultFlags = KPRFlags{
	KubeProxyReplacement:                   false,
	EnableSocketLB:                         false,
	EnableSocketLBHostnsOnly:               false,
	EnableSocketLBPodConnectionTermination: true,
}

func (def KPRFlags) Flags(flags *pflag.FlagSet) {
	flags.Bool("kube-proxy-replacement", def.KubeProxyReplacement, "Enable kube-proxy replacement")

	flags.Bool("bpf-lb-sock", def.EnableSocketLB, "Enable socket-based LB for E/W traffic")
	flags.Bool("bpf-lb-sock-hostns-only", def.EnableSocketLBHostnsOnly,
		"Skip socket LB for services when inside a pod namespace, in favor of service LB at the pod interface. Socket LB is still used when in the host namespace. Required by service mesh (e.g., Istio, Linkerd).")
	flags.Bool("bpf-lb-sock-terminate-pod-connections", def.EnableSocketLBPodConnectionTermination,
		"Enable terminating connections to deleted service backends when socket-LB is enabled")
	flags.MarkHidden("bpf-lb-sock-terminate-pod-connections")
}

type KPRConfig struct {
	KubeProxyReplacement                   bool
	EnableSocketLB                         bool
	EnableSocketLBHostnsOnly               bool
	EnableSocketLBPodConnectionTermination bool
}

func NewKPRConfig(flags KPRFlags) (KPRConfig, error) {
	//nolint:staticcheck
	cfg := KPRConfig{
		KubeProxyReplacement:                   flags.KubeProxyReplacement,
		EnableSocketLB:                         flags.EnableSocketLB,
		EnableSocketLBHostnsOnly:               flags.EnableSocketLBHostnsOnly,
		EnableSocketLBPodConnectionTermination: flags.EnableSocketLBPodConnectionTermination,
	}

	if flags.KubeProxyReplacement {
		cfg.EnableSocketLB = true
	}

	if !cfg.EnableSocketLB {
		cfg.EnableSocketLBHostnsOnly = false
	}

	return cfg, nil
}

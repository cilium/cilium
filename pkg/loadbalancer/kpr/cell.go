// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kpr

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/loadbalancer"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

var Cell = cell.Module(
	"kube-proxy-replacement-init",
	"Provides KPR initialization logic",
	cell.Provide(newKPRInitializer),
)

type KPRInitializer interface {
	// InitKubeProxyReplacementOptions will configure the loadbalancer config options according
	// to the KPRConfig.
	InitKubeProxyReplacementOptions() error

	// FinishKubeProxyReplacementInit finishes initialization of kube-proxy
	// replacement after all devices are known.
	FinishKubeProxyReplacementInit(devices []*tables.Device, directRoutingDevice string) error
}

type kprInitializerParams struct {
	cell.In

	Logger       *slog.Logger
	Sysctl       sysctl.Sysctl
	TunnelConfig tunnel.Config
	LBConfig     loadbalancer.Config
	WireguardCfg wgTypes.Config
}

func newKPRInitializer(params kprInitializerParams) KPRInitializer {
	return &kprInitializer{
		logger:       params.Logger,
		sysctl:       params.Sysctl,
		tunnelConfig: params.TunnelConfig,
		lbConfig:     params.LBConfig,
		wgCfg:        params.WireguardCfg,
	}
}

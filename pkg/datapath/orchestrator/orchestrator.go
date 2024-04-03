// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/proxy"
)

type orchestrator struct {
	params orchestratorParams
}

type orchestratorParams struct {
	cell.In

	Loader          types.Loader
	TunnelConfig    tunnel.Config
	MTU             mtu.MTU
	IPTablesManager *iptables.Manager
	Proxy           *proxy.Proxy
}

func newOrchestrator(params orchestratorParams) *orchestrator {
	return &orchestrator{
		params: params,
	}
}

func (o *orchestrator) Reinitialize(ctx context.Context) error {
	return o.params.Loader.Reinitialize(
		ctx,
		o.params.TunnelConfig,
		o.params.MTU.GetDeviceMTU(),
		o.params.IPTablesManager,
		o.params.Proxy,
	)
}

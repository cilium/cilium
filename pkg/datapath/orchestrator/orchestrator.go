// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

type orchestrator struct {
	params orchestratorParams
}

type orchestratorParams struct {
	cell.In

	Loader types.Loader
}

func newOrchestrator(params orchestratorParams) *orchestrator {
	return &orchestrator{
		params: params,
	}
}

func (o *orchestrator) Reinitialize(ctx context.Context, tunnelConfig tunnel.Config, deviceMTU int, iptMgr datapath.IptablesManager, p datapath.Proxy) error {
	return o.params.Loader.Reinitialize(ctx, tunnelConfig, deviceMTU, iptMgr, p)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"
)

type orchestrator struct {
	params orchestratorParams
}

type orchestratorParams struct {
	cell.In

	Loader              types.Loader
	TunnelConfig        tunnel.Config
	MTU                 mtu.MTU
	IPTablesManager     *iptables.Manager
	Proxy               *proxy.Proxy
	DB                  *statedb.DB
	Devices             statedb.Table[*tables.Device]
	NodeAddresses       statedb.Table[tables.NodeAddress]
	DirectRoutingDevice tables.DirectRoutingDevice
	LocalNodeStore      *node.LocalNodeStore
	NodeDiscovery       *nodediscovery.NodeDiscovery
}

func newOrchestrator(params orchestratorParams) *orchestrator {
	return &orchestrator{
		params: params,
	}
}

func (o *orchestrator) Reinitialize(ctx context.Context) error {
	// Wait until the local node has been populated by NodeDiscovery.
	o.params.NodeDiscovery.WaitForLocalNodeInit()

	localNode, err := o.params.LocalNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("get local node: %w", err)
	}

	rxn := o.params.DB.ReadTxn()
	directRoutingDevice, _ := o.params.DirectRoutingDevice.Get(ctx, rxn)

	// Construct the LocalNodeConfiguration that encapsulates the
	// local node's dynamic configuration.
	localNodeConfig, err := newLocalNodeConfig(
		option.Config,
		localNode,
		o.params.MTU,
		rxn,
		o.params.Devices,
		directRoutingDevice,
		o.params.NodeAddresses,
	)
	if err != nil {
		return fmt.Errorf("build LocalNodeConfiguration: %w", err)
	}

	return o.params.Loader.Reinitialize(
		ctx,
		localNodeConfig,
		o.params.TunnelConfig,
		o.params.IPTablesManager,
		o.params.Proxy,
	)
}

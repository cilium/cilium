// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"slices"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
)

// LoaderContext are the external inputs to the loader resolved by the orchestrator.
type LoaderContext struct {
	DeviceNames []string
	NodeAddrs   []tables.NodeAddress
}

func (lctx LoaderContext) Equal(other LoaderContext) bool {
	return slices.Equal(lctx.DeviceNames, other.DeviceNames) &&
		slices.Equal(lctx.NodeAddrs, other.NodeAddrs)
}

// Loader is an interface to abstract out loading of datapath programs.
type Loader interface {
	CallsMapPath(id uint16) string
	CustomCallsMapPath(id uint16) string
	DetachXDP(iface netlink.Link, bpffsBase, progName string) error
	EndpointHash(cfg types.EndpointConfiguration) (string, error)
	HostDatapathInitialized() <-chan struct{}
	Reinitialize(ctx context.Context, tunnelConfig tunnel.Config, deviceMTU int, iptMgr types.IptablesManager, p types.Proxy, lctx LoaderContext) error
	ReinitializeXDP(ctx context.Context, extraCArgs []string, lctx LoaderContext) error
	ReloadDatapath(ctx context.Context, ep types.Endpoint, lctx LoaderContext, stats *metrics.SpanStat) (err error)
	RestoreTemplates(stateDir string) error
	Unload(ep types.Endpoint)
}

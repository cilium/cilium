// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
)

type Loader interface {
	CallsMapPath(id uint16) string
	CustomCallsMapPath(id uint16) string
	DetachXDP(iface netlink.Link, bpffsBase, progName string) error
	EndpointHash(cfg types.EndpointConfiguration) (string, error)
	HostDatapathInitialized() <-chan struct{}
	Reinitialize(ctx context.Context, tunnelConfig tunnel.Config, deviceMTU int, iptMgr types.IptablesManager, p types.Proxy) error
	ReinitializeXDP(ctx context.Context, extraCArgs []string) error
	ReloadDatapath(ctx context.Context, ep types.Endpoint, stats *metrics.SpanStat) (err error)
	RestoreTemplates(stateDir string) error
	Unload(ep types.Endpoint)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"loader",
	"Loader",
	cell.Provide(NewLoader),
)

type Loader interface {
	CallsMapPath(id uint16) string
	CompileAndLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error
	CompileOrLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error
	CustomCallsMapPath(id uint16) string
	DetachXDP(iface netlink.Link, bpffsBase, progName string) error
	DeviceHasTCProgramLoaded(hostInterface string, checkEgress bool) (bool, error)
	ELFSubstitutions(ep datapath.Endpoint) (map[string]uint64, map[string]string)
	EndpointHash(cfg datapath.EndpointConfiguration) (string, error)
	HostDatapathInitialized() <-chan struct{}
	Reinitialize(ctx context.Context, o datapath.BaseProgramOwner, tunnelConfig tunnel.Config, deviceMTU int, iptMgr datapath.IptablesManager, p datapath.Proxy) error
	ReinitializeXDP(ctx context.Context, o datapath.BaseProgramOwner, extraCArgs []string) error
	ReloadDatapath(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) (err error)
	RestoreTemplates(stateDir string) error
	Unload(ep datapath.Endpoint)
}

// NewLoader returns a new loader.
func NewLoader(sc sysctl.Sysctl) Loader {
	return newLoader(sc)
}

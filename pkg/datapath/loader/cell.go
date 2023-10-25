// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
)

type Loader interface {
	CallsMapPath(id uint16) string
	CustomCallsMapPath(id uint16) string
	CompileAndLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error
	CompileOrLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error
	ReloadDatapath(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error
	EndpointHash(cfg datapath.EndpointConfiguration) (string, error)
	Unload(ep datapath.Endpoint)
	GetCompilationLock() *lock.RWMutex
	ELFSubstitutions(ep datapath.Endpoint) (map[string]uint64, map[string]string)

	Reinitialize(ctx context.Context, o datapath.BaseProgramOwner, tunnelConfig tunnel.Config, deviceMTU int, iptMgr datapath.IptablesManager, p datapath.Proxy) error
	HostDatapathInitialized() <-chan struct{}
	DeviceHasTCProgramLoaded(hostInterface string, checkEgress bool) (bool, error)
	SetupBaseDevice(mtu int) (netlink.Link, netlink.Link, error)
	ReinitializeXDP(ctx context.Context, o datapath.BaseProgramOwner, extraCArgs []string) error
}

var Cell = cell.Module(
	"loader",
	"Loader",
	cell.Provide(NewLoader),
)

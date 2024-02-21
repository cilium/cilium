// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"

	"github.com/vishvananda/netlink"
)

type Loader interface {
	CallsMapPath(id uint16) string
	CompileAndLoad(ctx context.Context, ep types.Endpoint, stats *metrics.SpanStat) error
	CompileOrLoad(ctx context.Context, ep types.Endpoint, stats *metrics.SpanStat) error
	CustomCallsMapPath(id uint16) string
	DetachXDP(iface netlink.Link, bpffsBase, progName string) error
	DeviceHasTCProgramLoaded(hostInterface string, checkEgress bool) (bool, error)
	ELFSubstitutions(ep types.Endpoint) (map[string]uint64, map[string]string)
	EndpointHash(cfg types.EndpointConfiguration) (string, error)
	HostDatapathInitialized() <-chan struct{}
	Reinitialize(ctx context.Context, o types.BaseProgramOwner, tunnelConfig tunnel.Config, deviceMTU int, iptMgr types.IptablesManager, p types.Proxy) error
	ReinitializeXDP(ctx context.Context, o types.BaseProgramOwner, extraCArgs []string) error
	ReloadDatapath(ctx context.Context, ep types.Endpoint, stats *metrics.SpanStat) (err error)
	RestoreTemplates(stateDir string) error
	Unload(ep types.Endpoint)
}

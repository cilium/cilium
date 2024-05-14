// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"io"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/node"
)

// LoaderContext are the external inputs to the loader resolved by the orchestrator.
// TODO: There's conceptual overlap with the LocalNodeConfiguration. Perhaps these could
// be unified so we don't need to pass both this and LoccalNodeConfiguration to the ConfigWriter.
// +deepequal-gen=true
type LoaderContext struct {
	LocalNode   node.LocalNode
	Devices     []*tables.Device
	DeviceNames []string
	NodeAddrs   []tables.NodeAddress
}

type Loader interface {
	CallsMapPath(id uint16) string
	CustomCallsMapPath(id uint16) string
	DetachXDP(iface netlink.Link, bpffsBase, progName string) error
	EndpointHash(cfg EndpointConfiguration) (string, error)
	HostDatapathInitialized() <-chan struct{}
	Reinitialize(ctx context.Context, tunnelConfig tunnel.Config, deviceMTU int, iptMgr IptablesManager, p Proxy, lctx LoaderContext) error
	ReinitializeXDP(ctx context.Context, extraCArgs []string, lctx LoaderContext) error
	ReloadDatapath(ctx context.Context, ep Endpoint, lctx LoaderContext, stats *metrics.SpanStat) (err error)
	RestoreTemplates(stateDir string) error
	Unload(ep Endpoint)
}

// PreFilter an interface for an XDP pre-filter.
type PreFilter interface {
	Enabled() bool
	WriteConfig(fw io.Writer)
	Dump(to []string) ([]string, int64)
	Insert(revision int64, cidrs []net.IPNet) error
	Delete(revision int64, cidrs []net.IPNet) error
}

// Proxy is any type which installs rules related to redirecting traffic to
// a proxy.
type Proxy interface {
	ReinstallRoutingRules() error
}

// IptablesManager manages iptables rules.
type IptablesManager interface {
	// InstallProxyRules creates the necessary datapath config (e.g., iptables
	// rules for redirecting host proxy traffic on a specific ProxyPort)
	InstallProxyRules(proxyPort uint16, localOnly bool, name string)

	// SupportsOriginalSourceAddr tells if the datapath supports
	// use of original source addresses in proxy upstream
	// connections.
	SupportsOriginalSourceAddr() bool

	// GetProxyPort fetches the existing proxy port configured for the
	// specified listener. Used early in bootstrap to reopen proxy ports.
	GetProxyPort(listener string) uint16

	// InstallNoTrackRules is explicitly called when a pod has valid
	// "policy.cilium.io/no-track-port" annotation.  When
	// InstallNoConntrackIptRules flag is set, a super set of v4 NOTRACK
	// rules will be automatically installed upon agent bootstrap (via
	// function addNoTrackPodTrafficRules) and this function will be
	// skipped.  When InstallNoConntrackIptRules is not set, this function
	// will be executed to install NOTRACK rules.  The rules installed by
	// this function is very specific, for now, the only user is
	// node-local-dns pods.
	InstallNoTrackRules(ip netip.Addr, port uint16)

	// See comments for InstallNoTrackRules.
	RemoveNoTrackRules(ip netip.Addr, port uint16)
}

// CompilationLock is a interface over a mutex, it is used by both the loader, daemon
// and endpoint manager to lock the compilation process. This is a bit of a layer violation
// since certain methods on the loader such as CompileAndLoad and CompileOrLoad expect the
// lock to be taken before being called.
//
// Once we have moved header file generation from the endpoint manager into the loader, we can
// remove this interface and have the loader manage the lock internally.
type CompilationLock interface {
	Lock()
	Unlock()
	RLock()
	RUnlock()
}

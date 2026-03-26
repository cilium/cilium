// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"io"

	"github.com/cilium/cilium/pkg/datapath/config"
	bigtcp "github.com/cilium/cilium/pkg/datapath/linux/bigtcp/types"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	proxy "github.com/cilium/cilium/pkg/proxy/types"
)

// Loader is an interface to abstract out loading of datapath programs.
type Loader interface {
	CallsMapPath(id uint16) string
	Unload(ep endpoint.Endpoint)
	HostDatapathInitialized() <-chan struct{}

	ReloadDatapath(ctx context.Context, ep endpoint.Endpoint, cfg *config.Config, stats *metrics.SpanStat) (string, error)
	EndpointHash(cfg endpoint.Config, lnCfg *config.Config) (string, error)
	ReinitializeHostDev(ctx context.Context, mtu int) error
	Reinitialize(ctx context.Context, cfg *config.Config, tunnelConfig tunnel.Config, iptMgr types.IptablesManager, p proxy.Proxy, bigtcp bigtcp.Configuration) error
	WriteEndpointConfig(w io.Writer, cfg endpoint.Config) error
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

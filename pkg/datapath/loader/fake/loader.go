// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"context"
	"io"

	"github.com/cilium/cilium/pkg/datapath/config"
	bigtcp "github.com/cilium/cilium/pkg/datapath/linux/bigtcp/types"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	proxy "github.com/cilium/cilium/pkg/proxy/types"
)

// Loader is an interface to abstract out loading of datapath programs.
type Loader struct{}

func (f *Loader) CompileOrLoad(ctx context.Context, ep endpoint.Endpoint, stats *metrics.SpanStat) error {
	panic("implement me")
}

func (f *Loader) ReloadDatapath(ctx context.Context, ep endpoint.Endpoint, lnc *config.Config, stats *metrics.SpanStat) (string, error) {
	panic("implement me")
}

func (f *Loader) EndpointHash(cfg endpoint.Config, _ *config.Config) (string, error) {
	panic("implement me")
}

func (f *Loader) Unload(ep endpoint.Endpoint) {
}

func (f *Loader) CallsMapPath(id uint16) string {
	return ""
}

func (f *Loader) ReinitializeHostDev(ctx context.Context, mtu int) error {
	return nil
}

// Reinitialize does nothing.
func (f *Loader) Reinitialize(ctx context.Context, lnc *config.Config, tunnelConfig tunnel.Config, iptMgr datapath.IptablesManager, p proxy.Proxy, bigtcp bigtcp.Configuration) error {
	return nil
}

func (f *Loader) HostDatapathInitialized() <-chan struct{} {
	return nil
}

func (f *Loader) DetachXDP(ifaceName string, bpffsBase, progName string) error {
	return nil
}

func (f *Loader) WriteEndpointConfig(w io.Writer, e endpoint.Config) error {
	return nil
}

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
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
)

// Loader is an interface to abstract out loading of datapath programs.
type FakeLoader struct{}

func (f *FakeLoader) CompileOrLoad(ctx context.Context, ep endpoint.Endpoint, stats *metrics.SpanStat) error {
	panic("implement me")
}

func (f *FakeLoader) ReloadDatapath(ctx context.Context, ep endpoint.Endpoint, lnc *config.Config, stats *metrics.SpanStat) (string, error) {
	panic("implement me")
}

func (f *FakeLoader) EndpointHash(cfg endpoint.Config, _ *config.Config) (string, error) {
	panic("implement me")
}

func (f *FakeLoader) Unload(ep endpoint.Endpoint) {
}

func (f *FakeLoader) CallsMapPath(id uint16) string {
	return ""
}

func (f *FakeLoader) ReinitializeHostDev(ctx context.Context, mtu int) error {
	return nil
}

// Reinitialize does nothing.
func (f *FakeLoader) Reinitialize(ctx context.Context, lnc *config.Config, tunnelConfig tunnel.Config, iptMgr datapath.IptablesManager, p datapath.Proxy, bigtcp bigtcp.Configuration) error {
	return nil
}

func (f *FakeLoader) HostDatapathInitialized() <-chan struct{} {
	return nil
}

func (f *FakeLoader) DetachXDP(ifaceName string, bpffsBase, progName string) error {
	return nil
}

func (f *FakeLoader) WriteEndpointConfig(w io.Writer, e endpoint.Config, lnc *config.Config) error {
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"io"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

// Loader is an interface to abstract out loading of datapath programs.
type FakeLoader struct{}

func (f *FakeLoader) CompileOrLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	panic("implement me")
}

func (f *FakeLoader) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, cfg *datapath.LocalNodeConfiguration, stats *metrics.SpanStat) (string, error) {
	panic("implement me")
}

func (f *FakeLoader) ReinitializeXDP(ctx context.Context, cfg *datapath.LocalNodeConfiguration, extraCArgs []string) error {
	panic("implement me")
}

func (f *FakeLoader) EndpointHash(cfg datapath.EndpointConfiguration, _ *datapath.LocalNodeConfiguration) (string, error) {
	panic("implement me")
}

func (f *FakeLoader) Unload(ep datapath.Endpoint) {
}

func (f *FakeLoader) CallsMapPath(id uint16) string {
	return ""
}

func (f *FakeLoader) CustomCallsMapPath(id uint16) string {
	return ""
}

func (f *FakeLoader) ReinitializeHostDev(ctx context.Context, mtu int) error {
	return nil
}

// Reinitialize does nothing.
func (f *FakeLoader) Reinitialize(ctx context.Context, cfg *datapath.LocalNodeConfiguration, tunnelConfig tunnel.Config, iptMgr datapath.IptablesManager, p datapath.Proxy) error {
	return nil
}

func (f *FakeLoader) HostDatapathInitialized() <-chan struct{} {
	return nil
}

func (f *FakeLoader) DetachXDP(ifaceName string, bpffsBase, progName string) error {
	return nil
}

func (f *FakeLoader) WriteEndpointConfig(w io.Writer, e datapath.EndpointConfiguration, cfg *datapath.LocalNodeConfiguration) error {
	return nil
}

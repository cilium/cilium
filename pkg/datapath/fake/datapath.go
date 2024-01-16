// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"context"
	"io"
	"net/netip"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
)

var _ datapath.Datapath = (*FakeDatapath)(nil)

type FakeDatapath struct {
	node           *FakeNodeHandler
	nodeAddressing datapath.NodeAddressing
	loader         datapath.Loader
	lbmap          *mockmaps.LBMockMap
}

// NewDatapath returns a new fake datapath
func NewDatapath() *FakeDatapath {
	return newDatapath(NewNodeAddressing())
}

func newDatapath(na datapath.NodeAddressing) *FakeDatapath {
	return &FakeDatapath{
		node:           NewNodeHandler(),
		nodeAddressing: na,
		loader: &fakeLoader{
			compilationLock: &lock.RWMutex{},
		},
		lbmap: mockmaps.NewLBMockMap(),
	}
}

// Node returns a fake handler for node events
func (f *FakeDatapath) Node() datapath.NodeHandler {
	return f.node
}

func (f *FakeDatapath) NodeIDs() datapath.NodeIDHandler {
	return f.node
}

func (f *FakeDatapath) NodeNeighbors() datapath.NodeNeighbors {
	return f.node
}

func (f *FakeDatapath) FakeNode() *FakeNodeHandler {
	return f.node
}

// LocalNodeAddressing returns a fake node addressing implementation of the
// local node
func (f *FakeDatapath) LocalNodeAddressing() datapath.NodeAddressing {
	return f.nodeAddressing
}

// WriteNodeConfig pretends to write the datapath configuration to the writer.
func (f *FakeDatapath) WriteNodeConfig(io.Writer, *datapath.LocalNodeConfiguration) error {
	return nil
}

// WriteNetdevConfig pretends to write the netdev configuration to a writer.
func (f *FakeDatapath) WriteNetdevConfig(io.Writer, datapath.DeviceConfiguration) error {
	return nil
}

// WriteTemplateConfig pretends to write the endpoint configuration to a writer.
func (f *FakeDatapath) WriteTemplateConfig(io.Writer, datapath.EndpointConfiguration) error {
	return nil
}

// WriteEndpointConfig pretends to write the endpoint configuration to a writer.
func (f *FakeDatapath) WriteEndpointConfig(io.Writer, datapath.EndpointConfiguration) error {
	return nil
}

func (f *FakeDatapath) InstallProxyRules(uint16, bool, bool, string) {
}

func (f *FakeDatapath) SupportsOriginalSourceAddr() bool {
	return false
}

func (m *FakeDatapath) GetProxyPort(name string) uint16 {
	return 0
}

func (m *FakeDatapath) InstallNoTrackRules(ip netip.Addr, port uint16) {
}

func (m *FakeDatapath) RemoveNoTrackRules(ip netip.Addr, port uint16) {
}

func (f *FakeDatapath) Loader() datapath.Loader {
	return f.loader
}

func (f *FakeDatapath) WireguardAgent() datapath.WireguardAgent {
	return nil
}

func (f *FakeDatapath) LBMap() datapath.LBMap {
	return f.lbmap
}

func (f *FakeDatapath) LBMockMap() *mockmaps.LBMockMap {
	return f.lbmap
}

func (f *FakeDatapath) BandwidthManager() datapath.BandwidthManager {
	return &BandwidthManager{}
}

// Loader is an interface to abstract out loading of datapath programs.
type fakeLoader struct {
	compilationLock *lock.RWMutex
}

func (f *fakeLoader) CompileAndLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	panic("implement me")
}

func (f *fakeLoader) CompileOrLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	panic("implement me")
}

func (f *fakeLoader) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	panic("implement me")
}

func (f *fakeLoader) EndpointHash(cfg datapath.EndpointConfiguration) (string, error) {
	panic("implement me")
}

func (f *fakeLoader) Unload(ep datapath.Endpoint) {
}

func (f *fakeLoader) CallsMapPath(id uint16) string {
	return ""
}

func (f *fakeLoader) CustomCallsMapPath(id uint16) string {
	return ""
}

// Reinitialize does nothing.
func (f *fakeLoader) Reinitialize(ctx context.Context, o datapath.BaseProgramOwner, tunnelConfig tunnel.Config, deviceMTU int, iptMgr datapath.IptablesManager, p datapath.Proxy) error {
	return nil
}

func (f *fakeLoader) HostDatapathInitialized() <-chan struct{} {
	return nil
}

func (f *fakeLoader) DeviceHasTCProgramLoaded(hostInterface string, checkEgress bool) (bool, error) {
	return false, nil
}

func (f *fakeLoader) ELFSubstitutions(ep datapath.Endpoint) (map[string]uint64, map[string]string) {
	return make(map[string]uint64), make(map[string]string)
}

func (f *fakeLoader) SetupBaseDevice(mtu int) (netlink.Link, netlink.Link, error) {
	panic("implement me")
}

func (f *fakeLoader) ReinitializeXDP(ctx context.Context, o datapath.BaseProgramOwner, extraCArgs []string) error {
	return nil
}

func (f *fakeLoader) GetCompilationLock() *lock.RWMutex {
	return f.compilationLock
}

// Copyright 2019-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fake

import (
	"context"
	"io"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
)

type fakeDatapath struct {
	node           datapath.NodeHandler
	nodeAddressing datapath.NodeAddressing
	loader         datapath.Loader
}

// NewDatapath returns a new fake datapath
func NewDatapath() datapath.Datapath {
	return &fakeDatapath{
		node:           NewNodeHandler(),
		nodeAddressing: NewNodeAddressing(),
		loader:         &fakeLoader{},
	}
}

// Node returns a fake handler for node events
func (f *fakeDatapath) Node() datapath.NodeHandler {
	return f.node
}

// LocalNodeAddressing returns a fake node addressing implementation of the
// local node
func (f *fakeDatapath) LocalNodeAddressing() datapath.NodeAddressing {
	return f.nodeAddressing
}

// WriteNodeConfig pretends to write the datapath configuration to the writer.
func (f *fakeDatapath) WriteNodeConfig(io.Writer, *datapath.LocalNodeConfiguration) error {
	return nil
}

// WriteNetdevConfig pretends to write the netdev configuration to a writer.
func (f *fakeDatapath) WriteNetdevConfig(io.Writer, datapath.DeviceConfiguration) error {
	return nil
}

// WriteTemplateConfig pretends to write the endpoint configuration to a writer.
func (f *fakeDatapath) WriteTemplateConfig(io.Writer, datapath.EndpointConfiguration) error {
	return nil
}

// WriteEndpointConfig pretends to write the endpoint configuration to a writer.
func (f *fakeDatapath) WriteEndpointConfig(io.Writer, datapath.EndpointConfiguration) error {
	return nil
}

func (f *fakeDatapath) InstallProxyRules(context.Context, uint16, bool, string) error {
	return nil
}

func (f *fakeDatapath) SupportsOriginalSourceAddr() bool {
	return false
}

func (f *fakeDatapath) InstallRules(ctx context.Context, ifName string, quiet, install bool) error {
	return nil
}

func (m *fakeDatapath) GetProxyPort(name string) uint16 {
	return 0
}

func (m *fakeDatapath) InstallNoTrackRules(IP string, port uint16, ipv6 bool) error {
	return nil
}

func (m *fakeDatapath) RemoveNoTrackRules(IP string, port uint16, ipv6 bool) error {
	return nil
}

func (f *fakeDatapath) Loader() datapath.Loader {
	return f.loader
}

func (f *fakeDatapath) WireguardAgent() datapath.WireguardAgent {
	return nil
}

// Loader is an interface to abstract out loading of datapath programs.
type fakeLoader struct {
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
func (f *fakeLoader) Reinitialize(ctx context.Context, o datapath.BaseProgramOwner, deviceMTU int, iptMgr datapath.IptablesManager, p datapath.Proxy) error {
	return nil
}

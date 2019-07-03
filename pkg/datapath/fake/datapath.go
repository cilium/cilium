// Copyright 2019 Authors of Cilium
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
	"io"

	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/datapath"
)

type fakeDatapath struct {
	node                datapath.NodeHandler
	nodeAddressing      datapath.NodeAddressing
	prefixLengthCounter *counter.PrefixLengthCounter
}

// NewDatapath returns a new fake datapath
func NewDatapath() datapath.Datapath {
	return &fakeDatapath{
		node:                NewNodeHandler(),
		nodeAddressing:      NewNodeAddressing(),
		prefixLengthCounter: newPrefixLengthCounter(),
	}
}

func newPrefixLengthCounter() *counter.PrefixLengthCounter {
	return counter.NewPrefixLengthCounter(4, 18)
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

func (f *fakeDatapath) InstallProxyRules(uint16, bool, string) error {
	return nil
}

func (f *fakeDatapath) RemoveProxyRules(uint16, bool, string) error {
	return nil
}

func (f *fakeDatapath) PrefixLengthCounter() *counter.PrefixLengthCounter {
	return f.prefixLengthCounter
}

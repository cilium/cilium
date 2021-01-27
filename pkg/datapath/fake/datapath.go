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

	"github.com/cilium/cilium/pkg/datapath"
)

type fakeDatapath struct {
	node           datapath.NodeHandler
	nodeAddressing datapath.NodeAddressing
	loader         datapath.Loader

	// Implement methods that need to mock out real behaviour in the following interfaces.
	datapath.ConfigWriter
	datapath.IptablesManager
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

// WriteEndpointConfig pretends to write the endpoint configuration to a writer.
func (f *fakeDatapath) WriteEndpointConfig(io.Writer, datapath.EndpointConfiguration) error {
	return nil
}

func (f *fakeDatapath) Loader() datapath.Loader {
	return f.loader
}

// Loader is an interface to abstract out loading of datapath programs.
type fakeLoader struct {
	// Implement methods that need to mock out real behaviour.
	datapath.Loader
}

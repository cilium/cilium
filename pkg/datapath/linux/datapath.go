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

package linux

import (
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/loader"
)

// DatapathConfiguration is the static configuration of the datapath. The
// configuration cannot change throughout the lifetime of a datapath object.
type DatapathConfiguration struct {
	// HostDevice is the name of the device to be used to access the host.
	HostDevice string
}

type linuxDatapath struct {
	datapath.ConfigWriter
	datapath.IptablesManager
	node           datapath.NodeHandler
	nodeAddressing datapath.NodeAddressing
	config         DatapathConfiguration
	loader         *loader.Loader
	wgAgent        datapath.WireguardAgent
}

// NewDatapath creates a new Linux datapath
func NewDatapath(cfg DatapathConfiguration, ruleManager datapath.IptablesManager, wgAgent datapath.WireguardAgent) datapath.Datapath {
	dp := &linuxDatapath{
		ConfigWriter:    &config.HeaderfileWriter{},
		IptablesManager: ruleManager,
		nodeAddressing:  NewNodeAddressing(),
		config:          cfg,
		loader:          loader.NewLoader(canDisableDwarfRelocations),
		wgAgent:         wgAgent,
	}

	dp.node = NewNodeHandler(cfg, dp.nodeAddressing, wgAgent)
	return dp
}

// Node returns the handler for node events
func (l *linuxDatapath) Node() datapath.NodeHandler {
	return l.node
}

// LocalNodeAddressing returns the node addressing implementation of the local
// node
func (l *linuxDatapath) LocalNodeAddressing() datapath.NodeAddressing {
	return l.nodeAddressing
}

func (l *linuxDatapath) Loader() datapath.Loader {
	return l.loader
}

func (l *linuxDatapath) WireguardAgent() datapath.WireguardAgent {
	return l.wgAgent
}

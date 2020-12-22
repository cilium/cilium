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
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// DatapathConfiguration is the static configuration of the datapath. The
// configuration cannot change throughout the lifetime of a datapath object.
type DatapathConfiguration struct {
	// HostDevice is the name of the device to be used to access the host.
	HostDevice string
	// EncryptInterface is the name of the device to be used for direct ruoting encryption
	EncryptInterface string
}

type linuxDatapath struct {
	datapath.ConfigWriter
	datapath.IptablesManager
	node           datapath.NodeHandler
	nodeAddressing datapath.NodeAddressing
	config         DatapathConfiguration
	loader         *loader.Loader
}

// NewDatapath creates a new Linux datapath
func NewDatapath(cfg DatapathConfiguration, ruleManager datapath.IptablesManager) datapath.Datapath {
	dp := &linuxDatapath{
		ConfigWriter:    &config.HeaderfileWriter{},
		IptablesManager: ruleManager,
		nodeAddressing:  NewNodeAddressing(),
		config:          cfg,
		loader:          loader.NewLoader(canDisableDwarfRelocations),
	}

	dp.node = NewNodeHandler(cfg, dp.nodeAddressing)

	if cfg.EncryptInterface != "" {
		if err := connector.DisableRpFilter(cfg.EncryptInterface); err != nil {
			log.WithField(logfields.Interface, cfg.EncryptInterface).Warn("Rpfilter could not be disabled, node to node encryption may fail")
		}
	}

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

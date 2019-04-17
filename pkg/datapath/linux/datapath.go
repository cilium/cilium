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
	"github.com/cilium/cilium/pkg/datapath/iptables"
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
	node           datapath.NodeHandler
	nodeAddressing datapath.NodeAddressing
	config         DatapathConfiguration
}

// NewDatapath creates a new Linux datapath
func NewDatapath(config DatapathConfiguration) datapath.Datapath {
	dp := &linuxDatapath{
		nodeAddressing: NewNodeAddressing(),
		config:         config,
	}

	dp.node = NewNodeHandler(config, dp.nodeAddressing)

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

func (l *linuxDatapath) InstallProxyRules(proxyPort uint16, ingress bool, name string) error {
	return iptables.InstallProxyRules(proxyPort, ingress, name)
}

func (l *linuxDatapath) RemoveProxyRules(proxyPort uint16, ingress bool, name string) error {
	return iptables.RemoveProxyRules(proxyPort, ingress, name)
}

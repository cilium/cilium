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
)

// Linux specific constants used in datapath to manage IPSec routing when enabled
const (
	// RouteTableIPSec is the default table ID to use for IPSec routing rules
	RouteTableIPSec = 200

	// RouteMarkDecrypt is the default route mark to use to indicate datapath
	// needs to decrypt a packet.
	RouteMarkDecrypt = 0x0D00

	// RouteMarkEncrypt is the default route mark to use to indicate datapath
	// needs to encrypt a packet.
	RouteMarkEncrypt = 0x0E00

	// RouteMarkMask is the mask required for the route mark value
	RouteMarkMask = 0xF00

	// IPSecProtocolID IP protocol ID for IPSec defined in RFC4303
	RouteProtocolIPSec = 50

	// TunnelDeviceName the default name of the tunnel device when using vxlan
	TunnelDeviceName = "cilium_vxlan"
)

// DatapathConfiguration is the static configuration of the datapath. The
// configuration cannot change throughout the lifetime of a datapath object.
type DatapathConfiguration struct {
	// HostDevice is the name of the device to be used to access the host.
	HostDevice string
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

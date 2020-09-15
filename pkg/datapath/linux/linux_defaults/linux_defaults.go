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

package linux_defaults

import (
	"time"
)

// Linux specific constants used in Linux datapath
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

	// MarkMultinodeNodeport is used for AWS ENI to mark traffic from
	// another node, so that it gets routed back through the relevant
	// interface.
	MarkMultinodeNodeport = 0x80

	// MaskMultinodeNodeport is the mask associated with the
	// RouterMarkNodePort
	MaskMultinodeNodeport = 0x80

	// IPSecProtocolID IP protocol ID for IPSec defined in RFC4303
	RouteProtocolIPSec = 50

	// RulePriorityIngress is the priority of the rule used for ingress routing
	// of endpoints. This priority is after encryption and proxy rules, and
	// before the local table priority.
	RulePriorityIngress = 20

	// RulePriorityEgress is the priority of the rule used for egress routing
	// of endpoints. This priority is after the local table priority.
	RulePriorityEgress = 110

	// RulePriorityNodeport is the priority of the rule used with AWS ENI to
	// make sure that lookups for multi-node NodePort traffic are NOT done
	// from the table for the VPC to which the endpoint's CIDR is
	// associated, but from the main routing table instead.
	// This priority is before the egress priority.
	RulePriorityNodeport = RulePriorityEgress - 1

	// TunnelDeviceName the default name of the tunnel device when using vxlan
	TunnelDeviceName = "cilium_vxlan"

	// IPSec offset value for node rules
	IPsecMaxKeyVersion = 16

	// IPsecMarkMask is the mask required for the IPsec SPI and encrypt/decrypt bits
	IPsecMarkMask = 0xFF00

	// IPsecMarkMaskIn is the mask required for IPsec to lookup encrypt/decrypt bits
	IPsecMarkMaskIn = 0x0F00

	// IPsecKeyDeleteDelay is the time to wait before removing old keys when
	// the IPsec key is changing.
	IPsecKeyDeleteDelay = 5 * time.Minute
)

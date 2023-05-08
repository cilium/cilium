// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux_defaults

import (
	"golang.org/x/sys/unix"
)

// Linux specific constants used in Linux datapath
const (
	// RouteTableIPSec is the default table ID to use for IPSec routing rules
	RouteTableIPSec = 200

	// RouteTableWireguard is the default table ID to use for Wireguard routing
	// rules
	RouteTableWireguard = 201

	// RouteTableVtep is the default table ID to use for VTEP routing rules
	RouteTableVtep = 202

	// RouteTableEgressGatewayInterfacesOffset is the offset for the per-ENI
	// egress gateway routing tables.
	// Each ENI interface will have its own table starting with this offset. It
	// is 300 because it is highly unlikely to collide with the main routing
	// table which is between 253-255. See ip-route(8).
	RouteTableEgressGatewayInterfacesOffset = 300

	// RouteTableInterfacesOffset is the offset for the per-ENI routing tables.
	// Each ENI interface will have its own table starting with this offset. It
	// is 10 because it is highly unlikely to collide with the main routing
	// table which is between 253-255. See ip-route(8).
	RouteTableInterfacesOffset = 10

	// RouteMarkDecrypt is the default route mark to use to indicate datapath
	// needs to decrypt a packet.
	RouteMarkDecrypt = 0x0D00

	// RouteMarkEncrypt is the default route mark to use to indicate datapath
	// needs to encrypt a packet.
	RouteMarkEncrypt = 0x0E00

	// RouteMarkMask is the mask required for the route mark value
	RouteMarkMask = 0xF00

	// RouteMarkToProxy is the default route mark to use to indicate
	// datapath needs to send the packet to the proxy.
	//
	// Specifically, this is used in the L7 ingress policy tunneling case
	// where after decryption, the packet is rerouted back into
	// `cilium_host` with said mark to indicate the destination as the
	// proxy.
	RouteMarkToProxy = MagicMarkIsToProxy

	// MarkMultinodeNodeport is used for AWS ENI to mark traffic from
	// another node, so that it gets routed back through the relevant
	// interface.
	MarkMultinodeNodeport = 0x80

	// MaskMultinodeNodeport is the mask associated with the
	// RouterMarkNodePort
	MaskMultinodeNodeport = 0x80

	// RTProto is the default protocol we install our fib rules and routes with
	RTProto = unix.RTPROT_KERNEL

	// RulePriorityWireguard is the priority of the rule used for routing packets to Wireguard device for encryption
	RulePriorityWireguard = 1

	// RulePriorityEgressGateway is the priority used in IP routes added by the manager.
	// This value was picked as it's lower than the ones used by Cilium
	// (RulePriorityEgressv2 = 111) or the AWS CNI (10) to install the IP
	// rules for routing EP traffic to the correct ENI interface
	RulePriorityEgressGateway = 8

	// RulePriorityIngress is the priority of the rule used for ingress routing
	// of endpoints. This priority is after encryption and proxy rules, and
	// before the local table priority.
	RulePriorityIngress = 20

	// RulePriorityLocalLookup is the priority for the local lookup rule which is
	// moved on init from 0
	RulePriorityLocalLookup = 100

	// RulePriorityEgress is the priority of the rule used for egress routing
	// of endpoints. This priority is after the local table priority.
	RulePriorityEgress = 110

	// RulePriorityEgress is the v2 of the priority of the rule used for egress
	// routing of endpoints. This priority is after the local table priority.
	//
	// Because of https://github.com/cilium/cilium/issues/14336, we must use a
	// new priority value to disambiguate which rules are still under the old
	// scheme.
	RulePriorityEgressv2 = 111

	// RulePriorityNodeport is the priority of the rule used with AWS ENI to
	// make sure that lookups for multi-node NodePort traffic are NOT done
	// from the table for the VPC to which the endpoint's CIDR is
	// associated, but from the main routing table instead.
	// This priority is before the egress priority.
	RulePriorityNodeport = RulePriorityEgress - 1

	// RulePriorityVtep is the priority of the rule used for routing packets to VTEP device
	RulePriorityVtep = 112

	// IPSec offset value for node rules
	IPsecMaxKeyVersion = 15

	// IPsecMarkMaskNodeID is the mask used for the node ID.
	IPsecMarkMaskNodeID = 0xFFFF0000

	// IPsecOldMarkMaskOut is the mask that was previously used. It can be
	// removed in Cilium v1.15.
	IPsecOldMarkMaskOut = 0xFF00

	// IPsecMarkMask is the mask required for the IPsec SPI, node ID, and encrypt/decrypt bits
	IPsecMarkMaskOut = IPsecOldMarkMaskOut | IPsecMarkMaskNodeID

	// IPsecMarkMaskIn is the mask required for IPsec to lookup encrypt/decrypt bits
	IPsecMarkMaskIn = 0x0F00

	// IPsecFwdPriority is the priority of the fwd rules placed by IPsec
	IPsecFwdPriority = 0x0B9F
)

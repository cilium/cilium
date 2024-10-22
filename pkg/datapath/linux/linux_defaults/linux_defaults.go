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

	// RouteTableVtep is the default table ID to use for VTEP routing rules
	RouteTableVtep = 202

	// RouteTableToProxy is the default table ID to use routing rules to the proxy.
	RouteTableToProxy = 2004

	// RouteTableFromProxy is the default table ID to use routing rules from the proxy.
	RouteTableFromProxy = 2005

	// RouteTableInterfacesOffset is the offset for the per-ENI routing tables.
	// Each ENI interface will have its own table starting with this offset. It
	// is 10 because it is highly unlikely to collide with the main routing
	// table which is between 253-255. See ip-route(8).
	RouteTableInterfacesOffset = 10

	// MarkProxyToWorld is the default mark to use to indicate that a packet
	// from proxy needs to be sent to the world.
	MarkProxyToWorld = 0x800

	// RouteMarkDecrypt is the default route mark to use to indicate datapath
	// needs to decrypt a packet.
	RouteMarkDecrypt = MagicMarkDecrypt

	// RouteMarkDecryptedOverlay is the output mark used for EncryptedOverlay
	// XFRM policies.
	//
	// When this mark is present on a packet it indicates that overlay traffic
	// was decrypted by XFRM and should be forwarded to a tunnel device for
	// decapsulation.
	RouteMarkDecryptedOverlay = MagicMarkDecryptedOverlay

	// RouteMarkEncrypt is the default route mark to use to indicate datapath
	// needs to encrypt a packet.
	RouteMarkEncrypt = MagicMarkEncrypt

	// RouteMarkMask is the mask required for the route mark value
	RouteMarkMask = 0xF00

	// OutputMarkMask is the mask to use in output-mark of XFRM states. It is
	// used to clear the node ID and the SPI from the packet mark.
	OutputMarkMask = 0xFFFFFF00

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

	// RTProto is the protocol we install our fib rules and routes with. Use the
	// kernel proto to make sure systemd-networkd doesn't interfere with these
	// rules (see networkd config directive ManageForeignRoutingPolicyRules, set
	// to 'yes' by default).
	RTProto = unix.RTPROT_KERNEL

	// RulePriorityToProxyIngress is the priority of the routing rule installed by
	// the proxy package for redirecting inbound packets to the proxy.
	RulePriorityToProxyIngress = 9

	// RulePriorityFromProxy is the priority of the routing rule installed by
	// the proxy package for redirecting packets from the proxy.
	RulePriorityFromProxy = 10

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

	// IPsecMarkBitMask is the mask used for the encrypt and decrypt bits.
	IPsecMarkBitMask = 0x0F00

	// IPsecOldMarkMaskOut is the mask that was previously used. It can be
	// removed in Cilium v1.17.
	IPsecOldMarkMaskOut = 0xFF00

	// IPsecMarkMask is the mask required for the IPsec SPI, node ID, and encrypt/decrypt bits
	IPsecMarkMaskOut = IPsecOldMarkMaskOut | IPsecMarkMaskNodeID

	// IPsecMarkMaskIn is the mask required for the IPsec node ID and encrypt/decrypt bits
	IPsecMarkMaskIn = IPsecMarkBitMask | IPsecMarkMaskNodeID

	// IPsecFwdPriority is the priority of the fwd rules placed by IPsec
	IPsecFwdPriority = 0x0B9F

	// IPsecXFRMMarkSPIShift defines how many bits the SPI is shifted when
	// encoded in a XfrmMark
	IPsecXFRMMarkSPIShift = 12
)

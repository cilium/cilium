// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
)

type IPsecAgent interface {
	Enabled() bool
	AuthKeySize() int
	SPI() uint8
	StartBackgroundJobs(NodeHandler) error
	UpsertIPsecEndpoint(params *IPSecParameters) (uint8, error)
	DeleteIPsecEndpoint(nodeID uint16) error
	DeleteXFRM(reqID int) error
	DeleteXfrmPolicyOut(nodeID uint16, dst *net.IPNet) error
}

type IPsecConfig interface {
	Enabled() bool
	EncryptedOverlayEnabled() bool
	UseCiliumInternalIP() bool
	DNSProxyInsecureSkipTransparentModeCheckEnabled() bool
}

type IPSecDir uint32

type IPSecParameters struct {
	// The BootID for the local host is used to determine if creation of the
	// policy should occur and for key derivation purposes.
	LocalBootID string
	// The BootID for the remote host is used to determine if creation of the
	// policy should occur and for key derivation purposes.
	RemoteBootID string
	// The direction of the created XFRM policy.
	Dir IPSecDir
	// The source subnet selector for the XFRM policy/state
	SourceSubnet *net.IPNet
	// The destination subnet selector for the XFRM policy/state
	DestSubnet *net.IPNet
	// The source security gateway IP used to define an IPsec tunnel mode SA
	// For OUT policies this is the resulting source address of an ESP encrypted
	// packet.
	// For IN/FWD this should identify the source SA address of the state which
	// decrypted the the packet.
	SourceTunnelIP *net.IP
	// The destination security gateway IP used to define an IPsec tunnel mode SA
	// For OUT policies this is the resulting destination address of an ESP encrypted
	// packet.
	// For IN/FWD this should identify the destination SA address of the state which
	// decrypted the the packet.
	DestTunnelIP *net.IP
	// The ReqID used for the resulting XFRM policy/state
	ReqID int
	// The remote node ID used for SPI identification and appropriate packet
	// mark matching.
	RemoteNodeID uint16
	// Whether to use a zero output mark or not.
	// This is useful when you want the resulting encrypted packet to immediately
	// handled by the stack and not Cilium's datapath.
	ZeroOutputMark bool
	// Whether the remote has been rebooted, this is used for bookkeping and
	// informs the policy/state creation methods whether the creation should
	// take place.
	RemoteRebooted bool
}

// Creates a new IPSecParameters. If template is provided make a copy of it
// instead of returning a new empty structure.
func NewIPSecParameters(template *IPSecParameters) *IPSecParameters {
	var p IPSecParameters
	if template != nil {
		p = *template
	}
	return &p
}

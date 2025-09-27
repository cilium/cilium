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

const (
	// EnableIPSec is the name of the option which enables the IPsec feature.
	EnableIPSec = "enable-ipsec"

	// Duration of the IPsec key rotation. After that time, we will clean the
	// previous IPsec key from the node.
	IPsecKeyRotationDuration = "ipsec-key-rotation-duration"

	// Enable watcher for IPsec key. If disabled, a restart of the agent will
	// be necessary on key rotations.
	EnableIPsecKeyWatcher = "enable-ipsec-key-watcher"

	// Enable caching for XfrmState for IPSec. Significantly reduces CPU usage
	// in large clusters.
	EnableIPSecXfrmStateCaching = "enable-ipsec-xfrm-state-caching"

	// IPSecKeyFile is the name of the option for ipsec key file
	IPSecKeyFile = "ipsec-key-file"

	// EnableIPSecEncryptedOverlay is the name of the option which enables
	// the EncryptedOverlay feature.
	//
	// This feature will encrypt overlay traffic before it leaves the cluster.
	EnableIPSecEncryptedOverlay = "enable-ipsec-encrypted-overlay"

	// Use the CiliumInternalIPs (vs. NodeInternalIPs) for IPsec encapsulation.
	UseCiliumInternalIPForIPsec = "use-cilium-internal-ip-for-ipsec"

	// DNSProxyInsecureSkipTransparentModeCheck is a hidden flag that allows users
	// to disable transparent mode even if IPSec is enabled
	DNSProxyInsecureSkipTransparentModeCheck = "dnsproxy-insecure-skip-transparent-mode-check"
)

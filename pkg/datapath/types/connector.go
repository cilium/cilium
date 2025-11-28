// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/netns"
)

type ConnectorMode string

const (
	ConnectorModeUnspec   = ConnectorMode("")
	ConnectorModeAuto     = ConnectorMode(option.DatapathModeAuto)
	ConnectorModeVeth     = ConnectorMode(option.DatapathModeVeth)
	ConnectorModeNetkit   = ConnectorMode(option.DatapathModeNetkit)
	ConnectorModeNetkitL2 = ConnectorMode(option.DatapathModeNetkitL2)
)

func (mode ConnectorMode) IsLayer2() bool {
	switch mode {
	case ConnectorModeVeth, ConnectorModeNetkitL2:
		return true
	default:
		return false
	}
}

func (mode ConnectorMode) IsNetkit() bool {
	switch mode {
	case ConnectorModeNetkit, ConnectorModeNetkitL2:
		return true
	default:
		return false
	}
}

func (mode ConnectorMode) IsVeth() bool {
	return mode == ConnectorModeVeth
}

func (mode ConnectorMode) String() string {
	switch mode {
	case ConnectorModeAuto:
		return option.DatapathModeAuto
	case ConnectorModeVeth:
		return option.DatapathModeVeth
	case ConnectorModeNetkit:
		return option.DatapathModeNetkit
	case ConnectorModeNetkitL2:
		return option.DatapathModeNetkitL2
	default:
		return ""
	}
}

func GetConnectorModeByName(mode string) ConnectorMode {
	switch mode {
	case option.DatapathModeAuto:
		return ConnectorModeAuto
	case option.DatapathModeVeth:
		return ConnectorModeVeth
	case option.DatapathModeNetkit:
		return ConnectorModeNetkit
	case option.DatapathModeNetkitL2:
		return ConnectorModeNetkitL2
	default:
		return ConnectorModeUnspec
	}
}

type ConnectorConfig interface {
	Reinitialize() error
	GetPodDeviceHeadroom() uint16
	GetPodDeviceTailroom() uint16
	GetConfiguredMode() ConnectorMode
	GetOperationalMode() ConnectorMode
	NewLinkPair(cfg LinkConfig, sysctl sysctl.Sysctl) (LinkPair, error)
	GetLinkCompatibility(ifName string) (ConnectorMode, bool, error)
}

// LinkConfig contains the GRO/GSO, MTU values and buffer margins to be configured on
// both sides of the created veth or netkit pair.
type LinkConfig struct {
	// EndpointID defines the container ID to which we are creating a new
	// linkpair. Set this if you want the connector to generate interface
	// names itself. Otherwise, set HostIfName and PeerIfName.
	EndpointID string

	// HostIfName defines the interface name as seen in the host namespace.
	HostIfName string

	// PeerIfName defines the interface name as seen in the container namespace.
	PeerIfName string

	// PeerNamespace defines the namespace the peer link should be moved into.
	PeerNamespace *netns.NetNS

	GROIPv6MaxSize int
	GSOIPv6MaxSize int

	GROIPv4MaxSize int
	GSOIPv4MaxSize int

	DeviceMTU      int
	DeviceHeadroom uint16
	DeviceTailroom uint16
}
type LinkPair interface {
	GetHostLink() netlink.Link
	GetPeerLink() netlink.Link
	GetMode() ConnectorMode
	Delete() error
}

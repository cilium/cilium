// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package awscni

import (
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
)

const (
	// awsCNIIfacePrefixVLAN is the prefix used by the AWS CNI to build the
	// name of the VLAN interface for SGP pods
	awsCNIIfacePrefixVLAN = "vlan.eth."
	// awsCNIInterfacePrefixSGPP the prefix used by the AWS CNI to build the
	// name of the host side interface for SGP pods
	awsCNIIfacePrefixSGPP = "vlan"
	// awsCNIIfacePrefixDummy is the name of the AWS CNI "dummy" interface
	awsCNIIfacePrefixDummy = "dummy"
)

// buildSGPPVLANIfaceName returns the name for the pod associated with
// the VLAN ID vlanID
func buildSGPPVLANIfaceName(vlanID string) string {
	return awsCNIIfacePrefixVLAN + vlanID
}

const (
	// awsCNISGPPRouteTableOffset is the route table offset from which
	// route SGPP pod route tables IDs start
	awsCNISGPPRouteTableOffset = 100
	// awsCNISGPPRulePriority is the priority level used for SGP pod
	// routing rules
	awsCNISGPPRulePriority = 10
)

// buildSGPPRouteTableID returns the table ID for the SGP pod associated
// with the VLAN vlanID. This is just the sum of the route table offset
// and VLAN ID
func buildSGPPRouteTableID(vlanID string) (int, error) {
	vlanIDInt, err := strconv.Atoi(vlanID)
	if err != nil {
		return 0, err
	}
	return awsCNISGPPRouteTableOffset + vlanIDInt, nil
}

// installSGPPProxyRules installs special routing rules for correctly
// routing traffic between an SGP pod and an ingress proxy
func installSGPPProxyRules(vlanID string, address net.IPNet) error {
	table, err := buildSGPPRouteTableID(vlanID)
	if err != nil {
		return err
	}

	var replaceRule func(route.Rule) error
	if len(address.IP) == net.IPv4len {
		replaceRule = route.ReplaceRule
	}
	if len(address.IP) == net.IPv6len {
		replaceRule = route.ReplaceRuleIPv6
	}

	if err = replaceRule(route.Rule{
		To:       &address,
		Priority: awsCNISGPPRulePriority,
		Table:    table,
		Mark:     uint32(linux_defaults.MagicMarkIsProxy),
		Mask:     linux_defaults.MagicMarkHostMask,
		Protocol: linux_defaults.RTProto,
	}); err != nil {
		return err
	}
	return replaceRule(route.Rule{
		From:     &address,
		Priority: awsCNISGPPRulePriority,
		Table:    table,
		Mark:     uint32(linux_defaults.MagicMarkIsProxy),
		Mask:     0xFFFFFFFF,
		Protocol: linux_defaults.RTProto,
	})
}

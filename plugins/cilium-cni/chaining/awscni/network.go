// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package awscni

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
)

// awsCNIVLANIfacePrefix is the prefix used by the AWS CNI for building
// interface names for SGP Pod VLAN interfaces
const awsCNIVLANIfacePrefix = "vlan.eth."

// buildSGPPodVLANIfaceName returns the name for the Pod associated with
// the VLAN ID vlanID
func buildSGPPodVLANIfaceName(vlanID string) string {
	return awsCNIVLANIfacePrefix + vlanID
}

// disableIfaceRPFilter disables the `rp_filter` network setting for the
// network interface iface
func disableIfaceRPFilter(iface string) error {
	return os.WriteFile(
		fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", iface),
		[]byte("0"),
		0644)
}

const (
	// awsCNISGPPodRouteTableOffset is the route table offset from which
	// route SGPP Pod route tables IDs start
	awsCNISGPPodRouteTableOffset = 100
	// awsCNISGPPodRulePriority is the priority level used for SGP Pod
	// routing rules
	awsCNISGPPodRulePriority = 10
)

// buildSGPPRouteTableID returns the table ID for the SGP Pod associated
// with the VLAN vlanID. This is just the sum of the route table offset
// and VLAN ID
func buildSGPPodRouteTableID(vlanID string) (int, error) {
	vlanIDInt, err := strconv.Atoi(vlanID)
	if err != nil {
		return 0, err
	}
	return awsCNISGPPodRouteTableOffset + vlanIDInt, nil
}

// installSGPPodProxyRules installs special routing rules for correctly
// routing traffic originating between SGP Pods and an ingress proxy
func installSGPPodProxyRules(vlanID string, address net.IPNet) error {
	table, err := buildSGPPodRouteTableID(vlanID)
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

	// traffic leaving and originating from ingress proxy to pod
	if err = replaceRule(route.Rule{
		To:       &address,
		Priority: awsCNISGPPodRulePriority,
		Table:    table,
		Mark:     uint32(linux_defaults.MagicMarkIsProxy),
		Mask:     linux_defaults.MagicMarkHostMask,
		Protocol: linux_defaults.RTProto,
	}); err != nil {
		return err
	}
	// traffic leaving ingress proxy, originating from remote peer
	return replaceRule(route.Rule{
		From:     &address,
		Priority: awsCNISGPPodRulePriority,
		Table:    table,
		Mark:     uint32(linux_defaults.MagicMarkIsProxy),
		Mask:     0xFFFFFFFF,
		Protocol: linux_defaults.RTProto,
	})
}

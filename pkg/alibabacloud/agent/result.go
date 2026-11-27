// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"

	"go4.org/netipx"

	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/types"
	"github.com/cilium/cilium/pkg/ipam"
)

func allocationResult(logger *slog.Logger, addr netip.Addr, pool ipam.Pool, enis map[string]alibabaCloudTypes.ENI) (*ipam.AllocationResult, error) {
	for _, eni := range enis {
		if eni.Type == alibabaCloudTypes.ENITypePrimary || !eniContainsIP(eni, addr) {
			continue
		}
		result := &ipam.AllocationResult{
			IP:              addr,
			IPPoolName:      pool,
			PrimaryMAC:      eni.MACAddress,
			InterfaceNumber: strconv.Itoa(alibabaCloudTypes.GetENIIndexFromTags(logger, eni.Tags)),
		}
		if addr.Is4() {
			if eni.VSwitch.CIDRBlock.IsValid() {
				// AlibabaCloud reserves the third-to-last IP of the subnet for the gateway.
				result.GatewayIP = netipx.PrefixLastIP(eni.VSwitch.CIDRBlock.Prefix).Prev().Prev()
			}
		} else {
			cidr := eni.VSwitch.IPv6CIDRBlock
			if !cidr.IsValid() || !cidr.Addr().Is6() || cidr.Addr().Is4In6() {
				return nil, fmt.Errorf("invalid IPv6 CIDR for AlibabaCloud vSwitch %s", eni.VSwitch.VSwitchID)
			}
			result.GatewayIP = netipx.PrefixLastIP(cidr.Prefix).Prev().Prev()
		}
		return result, nil
	}
	return nil, fmt.Errorf("unable to find AlibabaCloud ENI for IP %s", addr)
}

func eniContainsIP(eni alibabaCloudTypes.ENI, addr netip.Addr) bool {
	if slices.ContainsFunc(eni.PrivateIPSets, func(address alibabaCloudTypes.PrivateIPSet) bool {
		return address.PrivateIpAddress.Addr == addr
	}) {
		return true
	}
	for _, prefix := range eni.IPv6Prefixes {
		if !prefix.IsValid() {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

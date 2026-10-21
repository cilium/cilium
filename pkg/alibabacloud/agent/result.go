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
		if eni.Type == alibabaCloudTypes.ENITypePrimary || !slices.ContainsFunc(eni.PrivateIPSets, func(address alibabaCloudTypes.PrivateIPSet) bool {
			return address.PrivateIpAddress.Addr == addr && addr.Is4()
		}) {
			continue
		}
		result := &ipam.AllocationResult{
			IP:              addr,
			IPPoolName:      pool,
			PrimaryMAC:      eni.MACAddress,
			InterfaceNumber: strconv.Itoa(alibabaCloudTypes.GetENIIndexFromTags(logger, eni.Tags)),
		}
		if eni.VSwitch.CIDRBlock.IsValid() {
			// AlibabaCloud reserves the third-to-last IP of the subnet for the gateway.
			result.GatewayIP = netipx.PrefixLastIP(eni.VSwitch.CIDRBlock.Prefix).Prev().Prev()
		}
		return result, nil
	}
	return nil, fmt.Errorf("unable to find AlibabaCloud ENI for IP %s", addr)
}

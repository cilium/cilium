// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"fmt"
	"net/netip"
	"slices"

	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipmasq"
	"github.com/cilium/cilium/pkg/option"
)

func allocationResult(
	allocatedAddr netip.Addr,
	pool ipam.Pool,
	interfaces []azureTypes.AzureInterface,
	conf *option.DaemonConfig,
	ipMasqAgent *ipmasq.IPMasqAgent,
) (*ipam.AllocationResult, error) {
	for _, iface := range interfaces {
		if !slices.ContainsFunc(iface.Addresses, func(address azureTypes.AzureAddress) bool {
			return address.State == azureTypes.StateSucceeded && address.IP.Addr == allocatedAddr
		}) {
			continue
		}

		result := &ipam.AllocationResult{
			IP:              allocatedAddr,
			IPPoolName:      pool,
			PrimaryMAC:      iface.MAC,
			InterfaceNumber: "0",
		}
		if iface.Gateway.IsValid() {
			result.GatewayIP = iface.Gateway.Addr
		}

		return result, nil
	}

	return nil, fmt.Errorf("unable to find Azure interface for IP %s", allocatedAddr)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package addressesmanager

import (
	"net/netip"
)

type noOpAddressesManager struct{}

func NewNoOp() *noOpAddressesManager {
	return &noOpAddressesManager{}
}

func (_ *noOpAddressesManager) FindIPs(subnet netip.Prefix, addressesCount int32) (addresses []string, found bool) {
	return
}
func (_ *noOpAddressesManager) RegisterIPsUsed(ips []string, subnet netip.Prefix) {}
func (_ *noOpAddressesManager) RegisterIPsUnused(ips []string)                    {}

func ParseAlreadyAssignedError(assignErr error) (alreadyAssignedAddresses []string) {
	return
}

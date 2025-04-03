// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package addressesmanager

import (
	"net/netip"
)

type mock struct{}

func NewMock() *mock {
	return &mock{}
}

func (_ *mock) FindIPs(subnet netip.Prefix, addressesCount int32) (addresses []string, found bool) {
	return
}
func (_ *mock) RegisterIPsUsed(ips []string, subnet netip.Prefix) {}
func (_ *mock) RegisterIPsUnused(ips []string)                    {}

func ParseAlreadyAssignedError(assignErr error) (alreadyAssignedAddresses []string) {
	return
}

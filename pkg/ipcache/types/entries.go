// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"bytes"
	"net"

	"github.com/cilium/cilium/api/v1/models"
)

type IPListEntrySlice []*models.IPListEntry

func (s IPListEntrySlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less sorts the IPListEntry objects by CIDR prefix then IP address.
// Given that the same IP cannot map to more than one identity, no further
// sorting is performed.
func (s IPListEntrySlice) Less(i, j int) bool {
	_, iNet, _ := net.ParseCIDR(*s[i].Cidr)
	_, jNet, _ := net.ParseCIDR(*s[j].Cidr)
	iPrefixSize, _ := iNet.Mask.Size()
	jPrefixSize, _ := jNet.Mask.Size()
	if iPrefixSize == jPrefixSize {
		return bytes.Compare(iNet.IP, jNet.IP) < 0
	}
	return iPrefixSize < jPrefixSize
}

func (s IPListEntrySlice) Len() int {
	return len(s)
}

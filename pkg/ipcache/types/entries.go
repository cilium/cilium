// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipcachetypes

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

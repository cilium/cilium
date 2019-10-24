// Copyright 2019 Authors of Cilium
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

package ip

import (
	"bytes"
	"net"
	"sort"
)

// AddrsByMask is used to sort a list of IP addresses by their IPs.
// Implements sort.Interface.
type AddrsByMask []*net.IPAddr

func (s AddrsByMask) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s AddrsByMask) Less(i, j int) bool {
	iLength := len(s[i].IP)
	jLength := len(s[j].IP)
	if iLength == jLength {
		return bytes.Compare(s[i].IP, s[j].IP) < 0
	}
	return iLength < jLength
}

func (s AddrsByMask) Len() int {
	return len(s)
}

// Assert that AddrsByMask implements sort.Interface.
var _ sort.Interface = AddrsByMask{}

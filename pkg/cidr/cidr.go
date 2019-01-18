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

package cidr

import (
	"fmt"
	"net"
)

// NewCIDR returns a new CIDR using a net.IPNet
func NewCIDR(ipnet *net.IPNet) *CIDR {
	if ipnet == nil {
		return nil
	}

	return &CIDR{ipnet}
}

// CIDR is a network CIDR representation based on net.IPNet
type CIDR struct {
	*net.IPNet
}

// DeepCopy creates a deep copy of a CIDR
func (n *CIDR) DeepCopy() *CIDR {
	if n == nil {
		return nil
	}
	out := &CIDR{
		&net.IPNet{
			IP:   make([]byte, len(n.IP)),
			Mask: make([]byte, len(n.Mask)),
		},
	}
	copy(out.IP, n.IP)
	copy(out.Mask, n.Mask)
	return out
}

// ParseCIDR parses the CIDR string using net.ParseCIDR
func ParseCIDR(str string) (*CIDR, error) {
	_, ipnet, err := net.ParseCIDR(str)
	if err != nil {
		return nil, err
	}
	return NewCIDR(ipnet), nil
}

// MustParseCIDR parses the CIDR string using net.ParseCIDR and panics if the
// CIDR cannot be parsed
func MustParseCIDR(str string) *CIDR {
	c, err := ParseCIDR(str)
	if err != nil {
		panic(fmt.Sprintf("Unable to parse CIDR '%s': %s", str, err))
	}
	return c
}

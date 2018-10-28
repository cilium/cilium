// Copyright 2016-2017 Authors of Cilium
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

package addressing

import (
	"fmt"
	"net"
)

type CiliumIP interface {
	IPNet(ones int) *net.IPNet
	EndpointPrefix() *net.IPNet
	IP() net.IP
	String() string
	IsIPv6() bool
	GetFamilyString() string
	IsSet() bool
}

type CiliumIPv6 []byte

// NewCiliumIPv6 returns a IPv6 if the given `address` is:
// - An IPv6 address.
// - Node ID, bits from 112 to 120, must be different than 0
// - Endpoint ID, bits from 120 to 128, must be equal to 0
func NewCiliumIPv6(address string) (CiliumIPv6, error) {
	ip, _, err := net.ParseCIDR(address)
	if err != nil {
		ip = net.ParseIP(address)
		if ip == nil {
			return nil, fmt.Errorf("Invalid IPv6 address: %s", address)
		}
	}

	// As result of ParseIP, ip is either a valid IPv6 or IPv4 address. net.IP
	// represents both versions on 16 bytes, so a more reliable way to tell
	// IPv4 and IPv6 apart is to see if it fits 4 bytes
	ip4 := ip.To4()
	if ip4 != nil {
		return nil, fmt.Errorf("Not an IPv6 address: %s", address)
	}
	return DeriveCiliumIPv6(ip.To16()), nil
}

func DeriveCiliumIPv6(src net.IP) CiliumIPv6 {
	ip := make(CiliumIPv6, 16)
	copy(ip, src.To16())
	return ip
}

// IsSet returns true if the IP is set
func (ip CiliumIPv6) IsSet() bool {
	return ip.String() != ""
}

func (ip CiliumIPv6) IsIPv6() bool {
	return true
}

func (ip CiliumIPv6) IPNet(ones int) *net.IPNet {
	return &net.IPNet{
		IP:   ip.IP(),
		Mask: net.CIDRMask(ones, 128),
	}
}

func (ip CiliumIPv6) EndpointPrefix() *net.IPNet {
	return ip.IPNet(128)
}

func (ip CiliumIPv6) IP() net.IP {
	return net.IP(ip)
}

func (ip CiliumIPv6) String() string {
	if ip == nil {
		return ""
	}

	return net.IP(ip).String()
}

type CiliumIPv4 []byte

func NewCiliumIPv4(address string) (CiliumIPv4, error) {
	ip, _, err := net.ParseCIDR(address)
	if err != nil {
		ip = net.ParseIP(address)
		if ip == nil {
			return nil, fmt.Errorf("Invalid IPv4 address: %s", address)
		}
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("Not an IPv4 address")
	}
	return DeriveCiliumIPv4(ip4), nil
}

func DeriveCiliumIPv4(src net.IP) CiliumIPv4 {
	ip := make(CiliumIPv4, 4)
	copy(ip, src.To4())
	return ip
}

// IsSet returns true if the IP is set
func (ip CiliumIPv4) IsSet() bool {
	return ip.String() != ""
}

func (ip CiliumIPv4) IsIPv6() bool {
	return false
}

func (ip CiliumIPv4) IPNet(ones int) *net.IPNet {
	return &net.IPNet{
		IP:   net.IP(ip),
		Mask: net.CIDRMask(ones, 32),
	}
}

func (ip CiliumIPv4) EndpointPrefix() *net.IPNet {
	return ip.IPNet(32)
}

func (ip CiliumIPv4) IP() net.IP {
	return net.IP(ip)
}

func (ip CiliumIPv4) String() string {
	if ip == nil {
		return ""
	}

	return net.IP(ip).String()
}

// GetFamilyString returns the address family of ip as a string.
func (ip CiliumIPv4) GetFamilyString() string {
	return "IPv4"
}

// GetFamilyString returns the address family of ip as a string.
func (ip CiliumIPv6) GetFamilyString() string {
	return "IPv6"
}

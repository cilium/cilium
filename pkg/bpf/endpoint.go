// Copyright 2016-2019 Authors of Cilium
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

package bpf

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/types"
)

// Must be in sync with ENDPOINT_KEY_* in <bpf/lib/common.h>
const (
	EndpointKeyIPv4 uint8 = 1
	EndpointKeyIPv6 uint8 = 2
)

// EndpointKey represents the key value of the endpoints BPF map
//
// Must be in sync with struct endpoint_key in <bpf/lib/common.h>
// +k8s:deepcopy-gen=true
type EndpointKey struct {
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP     types.IPv6 `align:"$union0"`
	Family uint8      `align:"family"`
	Key    uint8      `align:"key"`
	Pad2   uint16     `align:"pad5"`
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *EndpointKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF key for users that
// use EndpointKey as a value in bpf maps
func (k *EndpointKey) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewEndpointKey returns an EndpointKey based on the provided IP address. The
// address family is automatically detected.
func NewEndpointKey(ip net.IP) EndpointKey {
	result := EndpointKey{}

	if ip4 := ip.To4(); ip4 != nil {
		result.Family = EndpointKeyIPv4
		copy(result.IP[:], ip4)
	} else {
		result.Family = EndpointKeyIPv6
		copy(result.IP[:], ip)
	}
	result.Key = 0

	return result
}

// ToIP converts the EndpointKey into a net.IP structure.
func (k EndpointKey) ToIP() net.IP {
	switch k.Family {
	case EndpointKeyIPv4:
		return k.IP[:4]
	case EndpointKeyIPv6:
		return k.IP[:]
	}
	return nil
}

// String provides a string representation of the EndpointKey.
func (k EndpointKey) String() string {
	if ip := k.ToIP(); ip != nil {
		return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", k.Key))
	}
	return "nil"
}

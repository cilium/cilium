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

package lbmap

import (
	"net"

	"github.com/cilium/cilium/pkg/bpf"
)

// BackendAddrID is the type of a service endpoint's unique identifier which
// consists of "IP:PORT"
type BackendAddrID string

// ServiceKey is the interface describing protocol independent key for services map v2.
//
// NOTE: ServiceKeyV2.String() output should match output of corresponding ServiceKey.String()!
type ServiceKeyV2 interface {
	bpf.MapKey

	// Return true if the key is of type IPv6
	IsIPv6() bool

	// Return the BPF map matching the key type
	Map() *bpf.Map

	// Return the BPF Weighted Round Robin map matching the key type
	RRMap() *bpf.Map

	// Set slave slot for the key
	SetSlave(slave int)

	// Get slave slot of the key
	GetSlave() int

	// Get frontend IP address
	GetAddress() net.IP

	// Get frontend port
	GetPort() uint16

	// Delete entry identified with the key from the matching map
	MapDelete() error

	// ToNetwork converts fields to network byte order.
	ToNetwork() ServiceKeyV2
}

// ServiceValue is the interface describing protocol independent value for services map v2.
type ServiceValueV2 interface {
	bpf.MapValue

	// Set the number of backends
	SetCount(int)

	// Get the number of backends
	GetCount() int

	// Set reverse NAT identifier
	SetRevNat(int)

	// Get reverse NAT identifier
	GetRevNat() int

	// Set weight
	SetWeight(uint16)

	// Get weight
	GetWeight() uint16

	// Set backend identifier
	SetBackendID(id uint16)

	// Get backend identifier
	GetBackendID() uint16

	// Returns a RevNatKey matching a ServiceValue
	RevNatKey() RevNatKey

	// Convert fields to network byte order.
	ToNetwork() ServiceValueV2
}

// BackendKey is the interface describing protocol independent backend key.
type BackendKey interface {
	bpf.MapKey

	// Return the BPF map matching the type
	Map() *bpf.Map

	// Set backend identifier
	SetID(uint16)

	// Get backend identifier
	GetID() uint16
}

// BackendValue is the interface describing protocol independent backend value.
type BackendValue interface {
	bpf.MapValue

	// Get backend address
	GetAddress() net.IP

	// Get backend port
	GetPort() uint16

	// Get backend address identifier (string of IP:Port)
	BackendAddrID() BackendAddrID

	// Convert fields to network byte order.
	ToNetwork() BackendValue
}

// Backend is the interface describing protocol independent backend used by services v2.
type Backend interface {
	// Return true if the value is of type IPv6
	IsIPv6() bool

	// Return the BPF map matching the type
	Map() *bpf.Map

	// Get backend identifier
	GetID() uint16

	// Get key of the backend entry
	GetKey() bpf.MapKey

	// Get value of the backend entry
	GetValue() BackendValue
}

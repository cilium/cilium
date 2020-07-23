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
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// ServiceKey is the interface describing protocol independent key for services map v2.
type ServiceKey interface {
	bpf.MapKey

	// Return true if the key is of type IPv6
	IsIPv6() bool

	// IsSurrogate returns true on zero-address
	IsSurrogate() bool

	// Return the BPF map matching the key type
	Map() *bpf.Map

	// Set backend slot for the key
	SetBackendSlot(slot int)

	// Get backend slot of the key
	GetBackendSlot() int

	// Set lookup scope for the key
	SetScope(scope uint8)

	// Get lookup scope for the key
	GetScope() uint8

	// Get frontend IP address
	GetAddress() net.IP

	// Get frontend port
	GetPort() uint16

	// Get protocol
	GetProtocol() uint8

	// Returns a RevNatValue matching a ServiceKey
	RevNatValue() RevNatValue

	// Delete entry identified with the key from the matching map
	MapDelete() error

	// ToNetwork converts fields to network byte order.
	ToNetwork() ServiceKey

	// ToHost converts fields to host byte order.
	ToHost() ServiceKey
}

// ServiceValue is the interface describing protocol independent value for services map v2.
type ServiceValue interface {
	bpf.MapValue

	// Set the number of backends
	SetCount(int)

	// Get the number of backends
	GetCount() int

	// Set reverse NAT identifier
	SetRevNat(int)

	// Get reverse NAT identifier
	GetRevNat() int

	// Set flags
	SetFlags(uint16)

	// Get flags
	GetFlags() uint16

	// Set timeout for sessionAffinity=clientIP
	SetSessionAffinityTimeoutSec(t uint32)

	// Set backend identifier
	SetBackendID(id loadbalancer.BackendID)

	// Get backend identifier
	GetBackendID() loadbalancer.BackendID

	// Returns a RevNatKey matching a ServiceValue
	RevNatKey() RevNatKey

	// Convert fields to network byte order.
	ToNetwork() ServiceValue

	// ToHost converts fields to host byte order.
	ToHost() ServiceValue
}

// BackendKey is the interface describing protocol independent backend key.
type BackendKey interface {
	bpf.MapKey

	// Return the BPF map matching the type
	Map() *bpf.Map

	// Set backend identifier
	SetID(loadbalancer.BackendID)

	// Get backend identifier
	GetID() loadbalancer.BackendID
}

// BackendValue is the interface describing protocol independent backend value.
type BackendValue interface {
	bpf.MapValue

	// Get backend address
	GetAddress() net.IP

	// Get backend port
	GetPort() uint16

	// Get backend protocol
	GetProtocol() uint8

	// Convert fields to network byte order.
	ToNetwork() BackendValue

	// ToHost converts fields to host byte order.
	ToHost() BackendValue
}

// Backend is the interface describing protocol independent backend used by services v2.
type Backend interface {
	// Return the BPF map matching the type
	Map() *bpf.Map

	// Get key of the backend entry
	GetKey() BackendKey

	// Get value of the backend entry
	GetValue() BackendValue
}

type RevNatKey interface {
	bpf.MapKey

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// ToNetwork converts fields to network byte order.
	ToNetwork() RevNatKey

	// Returns the key value
	GetKey() uint16

	// ToHost converts fields to host byte order.
	ToHost() RevNatKey
}

type RevNatValue interface {
	bpf.MapValue

	// ToNetwork converts fields to network byte order.
	ToNetwork() RevNatValue

	// ToHost converts fields to host byte order.
	ToHost() RevNatValue
}

// BackendIDByServiceIDSet is the type of a set for checking whether a backend
// belongs to a given service
type BackendIDByServiceIDSet map[uint16]map[uint16]struct{} // svc ID => backend ID

type SourceRangeSetByServiceID map[uint16][]*cidr.CIDR // svc ID => src range CIDRs

func svcFrontend(svcKey ServiceKey, svcValue ServiceValue) *loadbalancer.L3n4AddrID {
	p := loadbalancer.NewL4TypeFromNumber(svcKey.GetProtocol())
	feL3n4Addr := loadbalancer.NewL3n4Addr(p, svcKey.GetAddress(), svcKey.GetPort(), svcKey.GetScope())
	feL3n4AddrID := &loadbalancer.L3n4AddrID{
		L3n4Addr: *feL3n4Addr,
		ID:       loadbalancer.ID(svcValue.GetRevNat()),
	}
	return feL3n4AddrID
}

func svcBackend(backendID loadbalancer.BackendID, backend BackendValue) *loadbalancer.Backend {
	beIP := backend.GetAddress()
	bePort := backend.GetPort()
	p := loadbalancer.NewL4TypeFromNumber(backend.GetProtocol())
	beBackend := loadbalancer.NewBackend(backendID, p, beIP, bePort)
	return beBackend
}

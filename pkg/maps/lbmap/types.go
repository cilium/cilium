// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
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

	// Set proxy port for l7 loadbalancer services
	SetL7LBProxyPort(port uint16)

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

	// Get backend IP + clusterID
	GetIPCluster() cmtypes.AddrCluster

	// Get backend port
	GetPort() uint16

	// Get backend flags
	GetFlags() uint8

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

func svcFrontend(svcKey ServiceKey, svcValue ServiceValue) *loadbalancer.L3n4AddrID {
	feIP := svcKey.GetAddress()
	feAddrCluster := cmtypes.MustAddrClusterFromIP(feIP)
	feL3n4Addr := loadbalancer.NewL3n4Addr(loadbalancer.NONE, feAddrCluster, svcKey.GetPort(), svcKey.GetScope())
	feL3n4AddrID := &loadbalancer.L3n4AddrID{
		L3n4Addr: *feL3n4Addr,
		ID:       loadbalancer.ID(svcValue.GetRevNat()),
	}
	return feL3n4AddrID
}

func svcBackend(backendID loadbalancer.BackendID, backend BackendValue) *loadbalancer.Backend {
	beIP := backend.GetAddress()
	beAddrCluster := cmtypes.MustAddrClusterFromIP(beIP)
	bePort := backend.GetPort()
	beProto := loadbalancer.NONE
	beState := loadbalancer.GetBackendStateFromFlags(backend.GetFlags())
	beBackend := loadbalancer.NewBackendWithState(backendID, beProto, beAddrCluster, bePort, beState)
	return beBackend
}

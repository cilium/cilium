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
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
)

// BackendAddrID is the type of a service endpoint's unique identifier which
// consists of "IP:PORT"
type BackendAddrID string

// ServiceKey is the interface describing protocol independent key for services map.
type ServiceKey interface {
	bpf.MapKey

	// Returns true if the key is of type IPv6
	IsIPv6() bool

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// Returns the BPF Weighted Round Robin map matching the key type
	RRMap() *bpf.Map

	// Returns a RevNatValue matching a ServiceKey
	RevNatValue() RevNatValue

	// Returns the port set in the key or 0
	GetPort() uint16

	// Set the backend index (master: 0, backend: nth backend)
	SetBackend(int)

	// Return backend index
	GetBackend() int

	// ToNetwork converts fields to network byte order.
	ToNetwork() ServiceKey

	// ToHost converts fields to host byte order.
	ToHost() ServiceKey
}

// ServiceValue is the interface describing protocol independent value for services map.
type ServiceValue interface {
	bpf.MapValue

	// Returns a RevNatKey matching a ServiceValue
	RevNatKey() RevNatKey

	// Set the number of backends
	SetCount(int)

	// Get the number of backends
	GetCount() int

	// Set address to map to (left blank for master)
	SetAddress(net.IP) error

	// Set port to map to (left blank for master)
	SetPort(uint16)

	// Get the port number
	GetPort() uint16

	// Set reverse NAT identifier
	SetRevNat(int)

	// Set Weight
	SetWeight(uint16)

	// Get Weight
	GetWeight() uint16

	// ToNetwork converts fields to network byte order.
	ToNetwork() ServiceValue

	// ToHost converts fields to host byte order.
	ToHost() ServiceValue

	// Get BackendAddrID of the service value
	BackendAddrID() BackendAddrID

	// Returns true if the value is of type IPv6
	IsIPv6() bool
}

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

type RevNatKey interface {
	bpf.MapKey

	// Returns true if the key is of type IPv6
	IsIPv6() bool

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// ToNetwork converts fields to network byte order.
	ToNetwork() RevNatKey

	// Returns the key value
	GetKey() uint16
}

type RevNatValue interface {
	bpf.MapValue

	// ToNetwork converts fields to network byte order.
	ToNetwork() RevNatValue
}

type RRSeqValue struct {
	// Length of Generated sequence
	Count uint16

	// Generated Sequence
	Idx [MaxSeq]uint16
}

func (s *RRSeqValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }

func (s *RRSeqValue) String() string {
	return fmt.Sprintf("count=%d idx=%v", s.Count, s.Idx)
}

// l3n4Addr2ServiceKey converts the given l3n4Addr to a ServiceKey with the slave ID
// set to 0.
func l3n4Addr2ServiceKey(l3n4Addr loadbalancer.L3n4AddrID) ServiceKey {
	log.WithField(logfields.L3n4AddrID, l3n4Addr).Debug("converting L3n4Addr to ServiceKey")
	if l3n4Addr.IsIPv6() {
		return NewService6Key(l3n4Addr.IP, l3n4Addr.Port, 0)
	}
	return NewService4Key(l3n4Addr.IP, l3n4Addr.Port, 0)
}

// LBSVC2ServiceKeynValue transforms the SVC Cilium type into a bpf SVC type.
func LBSVC2ServiceKeynValue(svc *loadbalancer.LBSVC) (ServiceKey, []ServiceValue, error) {
	log.WithFields(logrus.Fields{
		"lbFrontend": svc.FE.String(),
		"lbBackend":  svc.BES,
	}).Debug("converting Cilium load-balancer service (frontend -> backend(s)) into BPF service")
	fe := l3n4Addr2ServiceKey(svc.FE)

	// Create a list of ServiceValues so we know everything is safe to put in the lb
	// map
	besValues := []ServiceValue{}
	for _, be := range svc.BES {
		beValue := fe.NewValue().(ServiceValue)
		if err := beValue.SetAddress(be.IP); err != nil {
			return nil, nil, err
		}
		beValue.SetPort(be.Port)
		beValue.SetRevNat(int(svc.FE.ID))
		beValue.SetWeight(be.Weight)

		besValues = append(besValues, beValue)
		log.WithFields(logrus.Fields{
			"lbFrontend": fe,
			"lbBackend":  beValue,
		}).Debug("associating frontend -> backend")
	}
	log.WithFields(logrus.Fields{
		"lbFrontend":        svc.FE.String(),
		"lbBackend":         svc.BES,
		logfields.ServiceID: fe,
		logfields.Object:    logfields.Repr(besValues),
	}).Debug("converted LBSVC (frontend -> backend(s)), to Service Key and Value")
	return fe, besValues, nil
}

// L3n4Addr2RevNatKeynValue converts the given L3n4Addr to a RevNatKey and RevNatValue.
func L3n4Addr2RevNatKeynValue(svcID loadbalancer.ServiceID, feL3n4Addr loadbalancer.L3n4Addr) (RevNatKey, RevNatValue) {
	if feL3n4Addr.IsIPv6() {
		return NewRevNat6Key(uint16(svcID)), NewRevNat6Value(feL3n4Addr.IP, feL3n4Addr.Port)
	}
	return NewRevNat4Key(uint16(svcID)), NewRevNat4Value(feL3n4Addr.IP, feL3n4Addr.Port)
}

// serviceKey2L3n4Addr converts the given svcKey to a L3n4Addr.
func serviceKey2L3n4Addr(svcKey ServiceKey) *loadbalancer.L3n4Addr {
	log.WithField(logfields.ServiceID, svcKey).Debug("creating L3n4Addr for ServiceKey")
	var (
		feIP   net.IP
		fePort uint16
	)
	if svcKey.IsIPv6() {
		svc6Key := svcKey.(*Service6Key)
		feIP = svc6Key.Address.IP()
		fePort = svc6Key.Port
	} else {
		svc4Key := svcKey.(*Service4Key)
		feIP = svc4Key.Address.IP()
		fePort = svc4Key.Port
	}
	return loadbalancer.NewL3n4Addr(loadbalancer.NONE, feIP, fePort)
}

// serviceKeynValue2FEnBE converts the given svcKey and svcValue to a frontend in the
// form of L3n4AddrID and backend in the form of L3n4Addr.
func serviceKeynValue2FEnBE(svcKey ServiceKey, svcValue ServiceValue) (*loadbalancer.L3n4AddrID, *loadbalancer.LBBackEnd) {
	var (
		beIP     net.IP
		svcID    loadbalancer.ServiceID
		bePort   uint16
		beWeight uint16
		beID     uint16
	)

	log.WithFields(logrus.Fields{
		logfields.ServiceID: svcKey,
		logfields.Object:    logfields.Repr(svcValue),
	}).Debug("converting ServiceKey and ServiceValue to frontend and backend")

	if svcKey.IsIPv6() {
		svc6Val := svcValue.(*Service6Value)
		svcID = loadbalancer.ServiceID(svc6Val.RevNat)
		beIP = svc6Val.Address.IP()
		bePort = svc6Val.Port
		beWeight = svc6Val.Weight
		beID = svc6Val.Count
	} else {
		svc4Val := svcValue.(*Service4Value)
		svcID = loadbalancer.ServiceID(svc4Val.RevNat)
		beIP = svc4Val.Address.IP()
		bePort = svc4Val.Port
		beWeight = svc4Val.Weight
		beID = svc4Val.Count
	}

	feL3n4Addr := serviceKey2L3n4Addr(svcKey)
	beLBBackEnd := loadbalancer.NewLBBackEnd(beID, loadbalancer.NONE, beIP, bePort, beWeight)

	feL3n4AddrID := &loadbalancer.L3n4AddrID{
		L3n4Addr: *feL3n4Addr,
		ID:       svcID,
	}

	return feL3n4AddrID, beLBBackEnd
}

func serviceValue2L3n4Addr(svcVal ServiceValue) *loadbalancer.L3n4Addr {
	var (
		beIP   net.IP
		bePort uint16
	)
	if svcVal.IsIPv6() {
		svc6Val := svcVal.(*Service6Value)
		beIP = svc6Val.Address.IP()
		bePort = svc6Val.Port
	} else {
		svc4Val := svcVal.(*Service4Value)
		beIP = svc4Val.Address.IP()
		bePort = svc4Val.Port
	}
	return loadbalancer.NewL3n4Addr(loadbalancer.NONE, beIP, bePort)
}

// RevNat6Value2L3n4Addr converts the given RevNat6Value to a L3n4Addr.
func revNat6Value2L3n4Addr(revNATV *RevNat6Value) *loadbalancer.L3n4Addr {
	return loadbalancer.NewL3n4Addr(loadbalancer.NONE, revNATV.Address.IP(), revNATV.Port)
}

// revNat4Value2L3n4Addr converts the given RevNat4Value to a L3n4Addr.
func revNat4Value2L3n4Addr(revNATV *RevNat4Value) *loadbalancer.L3n4Addr {
	return loadbalancer.NewL3n4Addr(loadbalancer.NONE, revNATV.Address.IP(), revNATV.Port)
}

// revNatValue2L3n4AddrID converts the given RevNatKey and RevNatValue to a L3n4AddrID.
func revNatValue2L3n4AddrID(revNATKey RevNatKey, revNATValue RevNatValue) *loadbalancer.L3n4AddrID {
	var (
		svcID loadbalancer.ServiceID
		be    *loadbalancer.L3n4Addr
	)
	if revNATKey.IsIPv6() {
		revNat6Key := revNATKey.(*RevNat6Key)
		svcID = loadbalancer.ServiceID(revNat6Key.Key)

		revNat6Value := revNATValue.(*RevNat6Value)
		be = revNat6Value2L3n4Addr(revNat6Value)
	} else {
		revNat4Key := revNATKey.(*RevNat4Key)
		svcID = loadbalancer.ServiceID(revNat4Key.Key)

		revNat4Value := revNATValue.(*RevNat4Value)
		be = revNat4Value2L3n4Addr(revNat4Value)
	}

	return &loadbalancer.L3n4AddrID{L3n4Addr: *be, ID: svcID}
}

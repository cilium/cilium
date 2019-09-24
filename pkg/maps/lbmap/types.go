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

	// Get address to map to (left blank for master)
	GetAddress() net.IP

	// Set port to map to (left blank for master)
	SetPort(uint16)

	// Get the port number
	GetPort() uint16

	// Set reverse NAT identifier
	SetRevNat(int)

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

	// Set backend identifier
	SetBackendID(id loadbalancer.BackendID)

	// Get backend identifier
	GetBackendID() loadbalancer.BackendID

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
	GetID() loadbalancer.BackendID

	// Get key of the backend entry
	GetKey() BackendKey

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

type idx [MaxSeq]uint16

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *idx) DeepCopyInto(out *idx) {
	copy(out[:], in[:])
	return
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type RRSeqValue struct {
	// Length of Generated sequence
	Count uint16

	// Generated Sequence
	Idx idx
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
func LBSVC2ServiceKeynValue(svc loadbalancer.LBSVC) (ServiceKey, []ServiceValue, error) {
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

// LBSVC2ServiceKeynValuenBackendValueV2 transforms the SVC Cilium type into a bpf SVC v2 type.
func LBSVC2ServiceKeynValuenBackendV2(svc *loadbalancer.LBSVC) (ServiceKeyV2, []ServiceValueV2, []Backend, error) {
	log.WithFields(logrus.Fields{
		"lbFrontend": svc.FE.String(),
		"lbBackend":  svc.BES,
	}).Debug("converting Cilium load-balancer service (frontend -> backend(s)) into BPF service v2")
	svcKey := l3n4Addr2ServiceKeyV2(svc.FE)

	backends := []Backend{}
	svcValues := []ServiceValueV2{}
	for _, be := range svc.BES {
		svcValue := svcKey.NewValue().(ServiceValueV2)
		backend, err := LBBackEnd2Backend(be)
		if err != nil {
			return nil, nil, nil, err
		}

		svcValue.SetRevNat(int(svc.FE.ID))
		svcValue.SetBackendID(loadbalancer.BackendID(be.ID))

		backends = append(backends, backend)
		svcValues = append(svcValues, svcValue)
		log.WithFields(logrus.Fields{
			"lbFrontend": svcKey,
			"lbBackend":  svcValue,
		}).Debug("associating frontend -> backend")
	}
	log.WithFields(logrus.Fields{
		"lbFrontend":        svc.FE.String(),
		"lbBackend":         svc.BES,
		logfields.ServiceID: svcKey,
		logfields.Object:    logfields.Repr(svcValues),
	}).Debug("converted LBSVC (frontend -> backend(s)), to ServiceKeyV2, ServiceValueV2 and Backend")
	return svcKey, svcValues, backends, nil
}

// serviceKey2L3n4Addr converts the given svcKey to a L3n4Addr.
func serviceKey2L3n4AddrV2(svcKey ServiceKeyV2) *loadbalancer.L3n4Addr {
	log.WithField(logfields.ServiceID, svcKey).Debug("creating L3n4Addr for ServiceKeyV2")

	feProto := loadbalancer.NONE
	feIP := svcKey.GetAddress()
	fePort := svcKey.GetPort()

	return loadbalancer.NewL3n4Addr(feProto, feIP, fePort)
}

func serviceKeynValuenBackendValue2FEnBE(svcKey ServiceKeyV2, svcValue ServiceValueV2,
	backendID loadbalancer.BackendID, backend BackendValue) (*loadbalancer.L3n4AddrID, *loadbalancer.LBBackEnd) {

	log.WithFields(logrus.Fields{
		logfields.ServiceID: svcKey,
		logfields.Object:    logfields.Repr(svcValue),
	}).Debug("converting ServiceKey, ServiceValue and Backend to frontend and backend v2")
	var beLBBackEnd *loadbalancer.LBBackEnd

	svcID := loadbalancer.ID(svcValue.GetRevNat())
	feL3n4Addr := serviceKey2L3n4AddrV2(svcKey)
	feL3n4AddrID := &loadbalancer.L3n4AddrID{
		L3n4Addr: *feL3n4Addr,
		ID:       svcID,
	}

	if backendID != 0 {
		beIP := backend.GetAddress()
		bePort := backend.GetPort()
		beProto := loadbalancer.NONE
		beLBBackEnd = loadbalancer.NewLBBackEnd(backendID, beProto, beIP, bePort)
	}

	return feL3n4AddrID, beLBBackEnd
}

// l3n4Addr2ServiceKeyV2 converts the given l3n4Addr to a ServiceKey (v2) with the slave ID
// set to 0.
func l3n4Addr2ServiceKeyV2(l3n4Addr loadbalancer.L3n4AddrID) ServiceKeyV2 {
	log.WithField(logfields.L3n4AddrID, l3n4Addr).Debug("converting L3n4Addr to ServiceKeyV2")
	if l3n4Addr.IsIPv6() {
		return NewService6KeyV2(l3n4Addr.IP, l3n4Addr.Port, u8proto.ANY, 0)
	}

	return NewService4KeyV2(l3n4Addr.IP, l3n4Addr.Port, u8proto.ANY, 0)
}

// LBBackEnd2Backend converts the loadbalancer backend type into a backend
// with a BPF key backing.
func LBBackEnd2Backend(be loadbalancer.LBBackEnd) (Backend, error) {
	if be.IsIPv6() {
		return NewBackend6(loadbalancer.BackendID(be.ID), be.IP, be.Port, u8proto.ANY)
	}

	return NewBackend4(loadbalancer.BackendID(be.ID), be.IP, be.Port, u8proto.ANY)
}

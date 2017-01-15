//
// Copyright 2016 Authors of Cilium
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
//
package lbmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
)

const (
	// Maximum number of entries in each hashtable
	maxEntries   = 65536
	maxFrontEnds = 256
	maxSeq       = 64
)

// Interface describing protocol independent key for services map
type ServiceKey interface {
	bpf.MapKey

	// Returns human readable string representation
	String() string

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

	// Convert between host byte order and map byte order
	Convert() ServiceKey
}

// Interface describing protocol independent value for services map
type ServiceValue interface {
	bpf.MapValue

	// Returns human readable string representation
	String() string

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

	// Set reverse NAT identifier
	SetRevNat(int)

	// Set Weight
	SetWeight(uint16)

	// Get Weight
	GetWeight() uint16

	// Convert between host byte order and map byte order
	Convert() ServiceValue
}

type ServiceRRSeq struct {
	Current uint64
	Count   uint16
	_       [3]uint16
	Idx     [maxSeq]uint16
}

func (s ServiceRRSeq) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&s) }

type ServiceRR struct {
	FE  types.L3n4Addr
	SEQ ServiceRRSeq
}

type WRRMap map[string]ServiceRR

func UpdateService(key ServiceKey, value ServiceValue) error {
	if key.GetBackend() != 0 && value.RevNatKey().GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0) in the Service Value")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.Convert(), value.Convert())
}

func UpdateServiceWeights(key ServiceKey, value *ServiceRRSeq) error {
	if _, err := key.RRMap().OpenOrCreate(); err != nil {
		return err
	}

	return key.RRMap().Update(key.Convert(), value)
}

func DeleteService(key ServiceKey) error {
	return key.Map().Delete(key.Convert())
}

func LookupService(key ServiceKey) (ServiceValue, error) {
	var svc ServiceValue

	val, err := key.Map().Lookup(key.Convert())
	if err != nil {
		return nil, err
	}

	if key.IsIPv6() {
		svc = val.(*Service6Value)
	} else {
		svc = val.(*Service4Value)
	}

	return svc.Convert(), nil
}

type RevNatKey interface {
	bpf.MapKey

	// Returns true if the key is of type IPv6
	IsIPv6() bool

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// Convert between host byte order and map byte order
	Convert() RevNatKey

	// Returns the key value
	GetKey() uint16
}

type RevNatValue interface {
	bpf.MapValue

	// Convert between host byte order and map byte order
	Convert() RevNatValue
}

func UpdateRevNat(key RevNatKey, value RevNatValue) error {
	if key.GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0)")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.Convert(), value.Convert())
}

func DeleteRevNat(key RevNatKey) error {
	return key.Map().Delete(key.Convert())
}

func LookupRevNat(key RevNatKey) (RevNatValue, error) {
	var revnat RevNatValue

	val, err := key.Map().Lookup(key.Convert())
	if err != nil {
		return nil, err
	}

	if key.IsIPv6() {
		revnat = val.(*RevNat6Value)
	} else {
		revnat = val.(*RevNat4Value)
	}

	return revnat.Convert(), nil
}

func gcd(x, y uint16) uint16 {
	for y != 0 {
		x, y = y, x%y
	}
	return x
}

type rrState struct {
	index int
	cw    uint16
}

func next(state *rrState, n int, max uint16, weights []uint16) uint16 {
	for {
		state.index = (state.index + 1) % n
		if state.index == 0 {
			state.cw = state.cw - 1
			if state.cw <= 0 {
				state.cw = max
			}
		}
		if weights[state.index] >= state.cw {
			return uint16(state.index)
		}
	}
}

func GenerateWrrSeq(weights []uint16) *ServiceRRSeq {
	var seq []uint16
	svcRRSeq := ServiceRRSeq{}

	n := len(weights)
	g := gcd(weights[0], weights[1])

	if g == 0 {
		return nil
	}

	for i := 2; i < n; i++ {
		g = gcd(g, weights[i])
	}

	sum := uint16(0)
	for i := 0; i < n; i++ {
		weights[i] = weights[i] / g
		sum += weights[i]
	}

	state := rrState{
		index: -1,
		cw:    uint16(0),
	}
	for i := 0; i < int(sum); i++ {
		seq = append(seq, next(&state, n, sum, weights))
	}
	copy(svcRRSeq.Idx[:], seq)
	svcRRSeq.Count = uint16(len(seq))
	svcRRSeq.Current = 0
	return &svcRRSeq
}

func UpdateWrrSeq(fe ServiceKey, weights []uint16) error {
	sum := uint16(0)
	for i := 0; i < len(weights); i++ {
		sum += weights[i]
	}
	if sum == 0 {
		return nil
	}
	svcRRSeq := GenerateWrrSeq(weights)
	if svcRRSeq != nil {
		return UpdateServiceWeights(fe, svcRRSeq)
	}
	return fmt.Errorf("unable to generate weighted round robin seq for %+v with value %+v", fe, weights)
}

// AddSVC2BPFMap adds the given bpf service to the bpf maps.
func AddSVC2BPFMap(fe ServiceKey, besValues []ServiceValue, addRevNAT bool, revNATID int) error {
	var err error
	var weights []uint16
	// Put all the backend services first
	nSvcs := 1
	nNonZeroWeights := 0
	for _, be := range besValues {
		fe.SetBackend(nSvcs)
		weights = append(weights, be.GetWeight())
		if be.GetWeight() != 0 {
			nNonZeroWeights++
		}
		if err := UpdateService(fe, be); err != nil {
			return fmt.Errorf("unable to update service %+v with the value %+v: %s", fe, be, err)
		}
		nSvcs++
	}

	if addRevNAT {
		zeroValue := fe.NewValue().(ServiceValue)
		zeroValue.SetRevNat(revNATID)
		revNATKey := zeroValue.RevNatKey()
		revNATValue := fe.RevNatValue()
		if err := UpdateRevNat(revNATKey, revNATValue); err != nil {
			return fmt.Errorf("unable to update reverse NAT %+v with value %+v, %s", revNATKey, revNATValue, err)
		}
		defer func() {
			if err != nil {
				DeleteRevNat(revNATKey)
			}
		}()
	}

	fe.SetBackend(0)
	zeroValue := fe.NewValue().(ServiceValue)
	zeroValue.SetCount(nSvcs - 1)
	zeroValue.SetWeight(uint16(nNonZeroWeights))

	err = UpdateService(fe, zeroValue)
	if err != nil {
		return fmt.Errorf("unable to update service %+v with the value %+v: %s", fe, zeroValue, err)
	}

	err = UpdateWrrSeq(fe, weights)
	if err != nil {
		return fmt.Errorf("unable to update service weights %+v with value %+v: %s", fe, weights, err)
	}

	return nil
}

// L3n4Addr2ServiceKey converts the given l3n4Addr to a ServiceKey with the slave ID
// set to 0.
func L3n4Addr2ServiceKey(l3n4Addr types.L3n4Addr) ServiceKey {
	if l3n4Addr.IsIPv6() {
		return NewService6Key(l3n4Addr.IP, l3n4Addr.Port, 0)
	} else {
		return NewService4Key(l3n4Addr.IP, l3n4Addr.Port, 0)
	}
}

// LBSVC2ServiceKeynValue transforms the SVC cilium type into a bpf SVC type.
func LBSVC2ServiceKeynValue(svc types.LBSVC) (ServiceKey, []ServiceValue, error) {

	fe := L3n4Addr2ServiceKey(svc.FE.L3n4Addr)

	// Create a list of ServiceValues so we know everything is safe to put in the lb
	// map
	besValues := []ServiceValue{}
	for _, be := range svc.BES {
		beValue := fe.NewValue().(ServiceValue)
		if err := beValue.SetAddress(be.Addr.IP); err != nil {
			return nil, nil, err
		}
		beValue.SetPort(uint16(be.Addr.Port))
		beValue.SetRevNat(int(svc.FE.ID))
		beValue.SetWeight(be.Weight)

		besValues = append(besValues, beValue)
	}

	return fe, besValues, nil
}

// L3n4Addr2RevNatKeynValue converts the given L3n4Addr to a RevNatKey and RevNatValue.
func L3n4Addr2RevNatKeynValue(svcID types.ServiceID, feL3n4Addr types.L3n4Addr) (RevNatKey, RevNatValue) {
	if feL3n4Addr.IsIPv6() {
		return NewRevNat6Key(uint16(svcID)), NewRevNat6Value(feL3n4Addr.IP, feL3n4Addr.Port)
	} else {
		return NewRevNat4Key(uint16(svcID)), NewRevNat4Value(feL3n4Addr.IP, feL3n4Addr.Port)
	}
}

// ServiceKey2L3n4Addr converts the given svcKey to a L3n4Addr.
func ServiceKey2L3n4Addr(svcKey ServiceKey) (*types.L3n4Addr, error) {
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

	return types.NewL3n4Addr(types.TCP, feIP, fePort)
}

// ServiceKeynValue2FEnBE converts the given svcKey and svcValue to a frontend int the
// form of L3n4AddrID and backend int he form of L3n4Addr.
func ServiceKeynValue2FEnBE(svcKey ServiceKey, svcValue ServiceValue) (*types.L3n4AddrID, *types.LBBackendServer, error) {
	var (
		beIP     net.IP
		svcID    types.ServiceID
		bePort   uint16
		beWeight uint16
	)
	if svcKey.IsIPv6() {
		svc6Val := svcValue.(*Service6Value)
		svcID = types.ServiceID(svc6Val.RevNat)
		beIP = svc6Val.Address.IP()
		bePort = svc6Val.Port
		beWeight = svc6Val.Weight
	} else {
		svc4Val := svcValue.(*Service4Value)
		svcID = types.ServiceID(svc4Val.RevNat)
		beIP = svc4Val.Address.IP()
		bePort = svc4Val.Port
		beWeight = svc4Val.Weight
	}

	feL3n4Addr, err := ServiceKey2L3n4Addr(svcKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create a new FE for service key %s: %s", svcKey, err)
	}

	beLBBackendServer, err := types.NewLBBackendServer(types.TCP, beIP, bePort, beWeight)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create a new BE for IP: %s Port: %d: %s", beIP, bePort, err)
	}

	feL3n4AddrID := &types.L3n4AddrID{
		L3n4Addr: *feL3n4Addr,
		ID:       svcID,
	}

	return feL3n4AddrID, beLBBackendServer, nil
}

// RevNat6Value2L3n4Addr converts the given RevNat6Value to a L3n4Addr.
func RevNat6Value2L3n4Addr(revNATV *RevNat6Value) (*types.L3n4Addr, error) {
	return types.NewL3n4Addr(types.TCP, revNATV.Address.IP(), revNATV.Port)
}

// RevNat4Value2L3n4Addr converts the given RevNat4Value to a L3n4Addr.
func RevNat4Value2L3n4Addr(revNATV *RevNat4Value) (*types.L3n4Addr, error) {
	return types.NewL3n4Addr(types.TCP, revNATV.Address.IP(), revNATV.Port)
}

// RevNatValue2L3n4AddrID converts the given RevNatKey and RevNatValue to a L3n4AddrID.
func RevNatValue2L3n4AddrID(revNATKey RevNatKey, revNATValue RevNatValue) (*types.L3n4AddrID, error) {
	var (
		svcID types.ServiceID
		be    *types.L3n4Addr
		err   error
	)
	if revNATKey.IsIPv6() {
		revNat6Key := revNATKey.(*RevNat6Key)
		svcID = types.ServiceID(revNat6Key.Key)

		revNat6Value := revNATValue.(*RevNat6Value)
		be, err = RevNat6Value2L3n4Addr(revNat6Value)
	} else {
		revNat4Key := revNATKey.(*RevNat4Key)
		svcID = types.ServiceID(revNat4Key.Key)

		revNat4Value := revNATValue.(*RevNat4Value)
		be, err = RevNat4Value2L3n4Addr(revNat4Value)
	}
	if err != nil {
		return nil, err
	}

	return &types.L3n4AddrID{L3n4Addr: *be, ID: svcID}, nil
}

// ServiceValue2LBBackendServer converts the svcValue to a LBBackendServer. The svcKey is necessary to
// determine which IP version svcValue is.
func ServiceValue2LBBackendServer(svcKey ServiceKey, svcValue ServiceValue) (*types.LBBackendServer, error) {
	var (
		feIP     net.IP
		fePort   uint16
		feWeight uint16
	)
	if svcKey.IsIPv6() {
		svc6Value := svcValue.(*Service6Value)
		feIP = svc6Value.Address.IP()
		fePort = svc6Value.Port
		feWeight = svc6Value.Weight
	} else {
		svc4Value := svcValue.(*Service4Value)
		feIP = svc4Value.Address.IP()
		fePort = svc4Value.Port
		feWeight = svc4Value.Weight
	}

	return types.NewLBBackendServer(types.TCP, feIP, fePort, feWeight)
}

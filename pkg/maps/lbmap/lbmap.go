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
	// MaxSeq is used by daemon for generating bpf define LB_RR_MAX_SEQ.
	MaxSeq = 31
)

// ServiceKey is the interface describing protocol independent key for services map.
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

// ServiceValue is the interface describing protocol independent value for services map.
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

type RRSeqValue struct {
	// Length of Generated sequence
	Count uint16

	// Generated Sequence
	Idx [MaxSeq]uint16
}

func (s RRSeqValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&s) }

func UpdateService(key ServiceKey, value ServiceValue) error {
	if key.GetBackend() != 0 && value.RevNatKey().GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0) in the Service Value")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.Convert(), value.Convert())
}

func DeleteService(key ServiceKey) error {
	err := key.Map().Delete(key.Convert())
	if err != nil {
		return err
	}
	return LookupAndDeleteServiceWeights(key)
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

// UpdateServiceWeights updates cilium_lb6_rr_seq or cilium_lb4_rr_seq bpf maps.
func UpdateServiceWeights(key ServiceKey, value *RRSeqValue) error {
	if _, err := key.RRMap().OpenOrCreate(); err != nil {
		return err
	}

	return key.RRMap().Update(key.Convert(), value)
}

// LookupAndDeleteServiceWeights deletes entry from cilium_lb6_rr_seq or cilium_lb4_rr_seq
func LookupAndDeleteServiceWeights(key ServiceKey) error {
	_, err := key.RRMap().Lookup(key.Convert())
	if err != nil {
		// Ignore if entry is not found.
		return nil
	}

	return key.RRMap().Delete(key.Convert())
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

// gcd computes the gcd of two numbers.
func gcd(x, y uint16) uint16 {
	for y != 0 {
		x, y = y, x%y
	}
	return x
}

// generateWrrSeq generates a wrr sequence based on provided weights.
func generateWrrSeq(weights []uint16) (*RRSeqValue, error) {
	svcRRSeq := RRSeqValue{}

	n := len(weights)
	if n < 2 {
		return nil, fmt.Errorf("needs at least 2 weights")
	}

	g := uint16(0)
	for i := 0; i < n; i++ {
		if weights[i] != 0 {
			g = gcd(g, weights[i])
		}
	}

	// This means all the weights are 0.
	if g == 0 {
		return nil, fmt.Errorf("all specified weights are 0")
	}

	sum := uint16(0)
	for i := range weights {
		// Normalize the weights.
		weights[i] = weights[i] / g
		sum += weights[i]
	}

	// Check if Generated seq fits in our array.
	if int(sum) > len(svcRRSeq.Idx) {
		return nil, fmt.Errorf("sum of normalized weights exceeds %d", len(svcRRSeq.Idx))
	}

	// Generate the Sequence.
	i := uint16(0)
	k := uint16(0)
	for {
		j := uint16(0)
		for j < weights[k] {
			svcRRSeq.Idx[i] = k
			i++
			j++
		}
		if i >= sum {
			break
		}
		k++
	}
	svcRRSeq.Count = sum
	return &svcRRSeq, nil
}

// UpdateWrrSeq updates bpf map with the generated wrr sequence.
func UpdateWrrSeq(fe ServiceKey, weights []uint16) error {
	sum := uint16(0)
	for _, v := range weights {
		sum += v
	}
	if sum == 0 {
		return nil
	}
	svcRRSeq, err := generateWrrSeq(weights)
	if err != nil {
		return fmt.Errorf("unable to generate weighted round robin seq for %s with value %+v: %s", fe.String(), weights, err)
	}
	return UpdateServiceWeights(fe, svcRRSeq)
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
		return fmt.Errorf("unable to update service weights for %s with value %+v: %s", fe.String(), weights, err)
	}

	return nil
}

// L3n4Addr2ServiceKey converts the given l3n4Addr to a ServiceKey with the slave ID
// set to 0.
func L3n4Addr2ServiceKey(l3n4Addr types.L3n4Addr) ServiceKey {
	if l3n4Addr.IsIPv6() {
		return NewService6Key(l3n4Addr.IP, l3n4Addr.Port, 0)
	}
	return NewService4Key(l3n4Addr.IP, l3n4Addr.Port, 0)
}

// LBSVC2ServiceKeynValue transforms the SVC cilium type into a bpf SVC type.
func LBSVC2ServiceKeynValue(svc types.LBSVC) (ServiceKey, []ServiceValue, error) {

	fe := L3n4Addr2ServiceKey(svc.FE.L3n4Addr)

	// Create a list of ServiceValues so we know everything is safe to put in the lb
	// map
	besValues := []ServiceValue{}
	for _, be := range svc.BES {
		beValue := fe.NewValue().(ServiceValue)
		if err := beValue.SetAddress(be.IP); err != nil {
			return nil, nil, err
		}
		beValue.SetPort(uint16(be.Port))
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
	}
	return NewRevNat4Key(uint16(svcID)), NewRevNat4Value(feL3n4Addr.IP, feL3n4Addr.Port)
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

// ServiceKeynValue2FEnBE converts the given svcKey and svcValue to a frontend in the
// form of L3n4AddrID and backend in the form of L3n4Addr.
func ServiceKeynValue2FEnBE(svcKey ServiceKey, svcValue ServiceValue) (*types.L3n4AddrID, *types.LBBackEnd, error) {
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

	beLBBackEnd, err := types.NewLBBackEnd(types.TCP, beIP, bePort, beWeight)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create a new BE for IP: %s Port: %d: %s", beIP, bePort, err)
	}

	feL3n4AddrID := &types.L3n4AddrID{
		L3n4Addr: *feL3n4Addr,
		ID:       svcID,
	}

	return feL3n4AddrID, beLBBackEnd, nil
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

// ServiceValue2LBBackEnd converts the svcValue to a LBBackEnd. The svcKey is necessary to
// determine which IP version svcValue is.
func ServiceValue2LBBackEnd(svcKey ServiceKey, svcValue ServiceValue) (*types.LBBackEnd, error) {
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

	return types.NewLBBackEnd(types.TCP, feIP, fePort, feWeight)
}

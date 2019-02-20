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
	"github.com/cilium/cilium/pkg/byteorder"
)

var (
	// Service6Map represents the BPF map for services in IPv6 load balancer
	Service6Map = bpf.NewMap("cilium_lb6_services",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Service6Key{})),
		int(unsafe.Sizeof(Service6Value{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			svcKey, svcVal := Service6Key{}, Service6Value{}

			if err := bpf.ConvertKeyValue(key, value, &svcKey, &svcVal); err != nil {
				return nil, nil, err
			}

			return svcKey.ToNetwork(), svcVal.ToNetwork(), nil
		}).WithCache()
	// RevNat6Map represents the BPF map for reverse NAT in IPv6 load balancer
	RevNat6Map = bpf.NewMap("cilium_lb6_reverse_nat",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(RevNat6Key{})),
		int(unsafe.Sizeof(RevNat6Value{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			var ukey uint16
			var revNat RevNat6Value

			if err := bpf.ConvertKeyValue(key, value, &ukey, &revNat); err != nil {
				return nil, nil, err
			}

			revKey := NewRevNat6Key(ukey)

			return revKey.ToNetwork(), revNat.ToNetwork(), nil
		}).WithCache()
	// RRSeq6Map represents the BPF map for wrr sequences in IPv6 load balancer
	RRSeq6Map = bpf.NewMap("cilium_lb6_rr_seq",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Service6Key{})),
		int(unsafe.Sizeof(RRSeqValue{})),
		maxFrontEnds,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			svcKey, svcVal := Service6Key{}, RRSeqValue{}

			if err := bpf.ConvertKeyValue(key, value, &svcKey, &svcVal); err != nil {
				return nil, nil, err
			}

			return svcKey.ToNetwork(), &svcVal, nil
		}).WithCache()
)

// Service6Key must match 'struct lb6_key' in "bpf/lib/common.h".
type Service6Key struct {
	Address types.IPv6 `align:"address"`
	Port    uint16     `align:"dport"`
	Slave   uint16     `align:"slave"`
}

func NewService6Key(ip net.IP, port uint16, slave uint16) *Service6Key {
	key := Service6Key{
		Port:  port,
		Slave: slave,
	}

	copy(key.Address[:], ip.To16())

	return &key
}

func (k Service6Key) IsIPv6() bool               { return true }
func (k Service6Key) Map() *bpf.Map              { return Service6Map }
func (k Service6Key) RRMap() *bpf.Map            { return RRSeq6Map }
func (k Service6Key) NewValue() bpf.MapValue     { return &Service6Value{} }
func (k *Service6Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Service6Key) GetPort() uint16           { return k.Port }
func (k *Service6Key) SetPort(port uint16)       { k.Port = port }
func (k *Service6Key) SetBackend(backend int)    { k.Slave = uint16(backend) }
func (k *Service6Key) GetBackend() int           { return int(k.Slave) }

// ToNetwork converts Service6Key to network byte order.
func (k *Service6Key) ToNetwork() ServiceKey {
	n := *k
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

// ToHost converts Service6Key to host byte order.
func (k *Service6Key) ToHost() ServiceKey {
	n := *k
	n.Port = byteorder.NetworkToHost(n.Port).(uint16)
	return &n
}

func (k *Service6Key) String() string {
	return fmt.Sprintf("[%s]:%d", k.Address, k.Port)
}

func (k *Service6Key) RevNatValue() RevNatValue {
	return &RevNat6Value{
		Address: k.Address,
		Port:    k.Port,
	}
}

// Service6Value must match 'struct lb6_service' in "bpf/lib/common.h".
type Service6Value struct {
	Address types.IPv6 `align:"target"`
	Port    uint16     `align:"port"`
	Count   uint16     `align:"count"`
	RevNat  uint16     `align:"rev_nat_index"`
	Weight  uint16     `align:"weight"`
}

func NewService6Value(count uint16, target net.IP, port uint16, revNat uint16, weight uint16) *Service6Value {
	svc := Service6Value{
		Count:  count,
		Port:   port,
		RevNat: revNat,
		Weight: weight,
	}

	copy(svc.Address[:], target.To16())

	return &svc
}

func (s *Service6Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }
func (s *Service6Value) SetPort(port uint16)         { s.Port = port }
func (s *Service6Value) SetCount(count int)          { s.Count = uint16(count) }
func (s *Service6Value) GetCount() int               { return int(s.Count) }
func (s *Service6Value) SetRevNat(id int)            { s.RevNat = uint16(id) }
func (s *Service6Value) RevNatKey() RevNatKey        { return &RevNat6Key{s.RevNat} }
func (s *Service6Value) SetWeight(weight uint16)     { s.Weight = weight }
func (s *Service6Value) GetWeight() uint16           { return s.Weight }

func (s *Service6Value) SetAddress(ip net.IP) error {
	if ip.To4() != nil {
		return fmt.Errorf("Not an IPv6 address")
	}

	copy(s.Address[:], ip.To16())
	return nil
}

// ToNetwork converts Service6Value ports to network byte order.
func (s *Service6Value) ToNetwork() ServiceValue {
	n := *s
	n.RevNat = byteorder.HostToNetwork(n.RevNat).(uint16)
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	n.Weight = byteorder.HostToNetwork(n.Weight).(uint16)
	return &n
}

// ToHost converts Service6Value ports to host byte order.
func (s *Service6Value) ToHost() ServiceValue {
	n := *s
	n.RevNat = byteorder.NetworkToHost(n.RevNat).(uint16)
	n.Port = byteorder.NetworkToHost(n.Port).(uint16)
	n.Weight = byteorder.NetworkToHost(n.Weight).(uint16)
	return &n
}

func (s *Service6Value) String() string {
	return fmt.Sprintf("[%s]:%d (%d)", s.Address, s.Port, s.RevNat)
}

type RevNat6Key struct {
	Key uint16
}

func NewRevNat6Key(value uint16) *RevNat6Key {
	return &RevNat6Key{value}
}

func (v *RevNat6Key) IsIPv6() bool              { return true }
func (v *RevNat6Key) Map() *bpf.Map             { return RevNat6Map }
func (v *RevNat6Key) NewValue() bpf.MapValue    { return &RevNat6Value{} }
func (v *RevNat6Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *RevNat6Key) String() string            { return fmt.Sprintf("%d", v.Key) }
func (v *RevNat6Key) GetKey() uint16            { return v.Key }

// ToNetwork converts RevNat6Key to network byte order.
func (v *RevNat6Key) ToNetwork() RevNatKey {
	n := *v
	n.Key = byteorder.HostToNetwork(n.Key).(uint16)
	return &n
}

type RevNat6Value struct {
	Address types.IPv6
	Port    uint16
}

func NewRevNat6Value(ip net.IP, port uint16) *RevNat6Value {
	revNat := RevNat6Value{
		Port: port,
	}

	copy(revNat.Address[:], ip.To16())

	return &revNat
}

func (v *RevNat6Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *RevNat6Value) String() string              { return fmt.Sprintf("%s:%d", v.Address, v.Port) }

// ToNetwork converts RevNat6Value to network byte order.
func (v *RevNat6Value) ToNetwork() RevNatValue {
	n := *v
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

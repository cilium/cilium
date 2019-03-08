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
	"github.com/cilium/cilium/pkg/u8proto"
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
	Service6MapV2 = bpf.NewMap("cilium_lb6_services_v2",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Service6KeyV2{})),
		int(unsafe.Sizeof(Service6ValueV2{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			svcKey, svcVal := Service6KeyV2{}, Service6ValueV2{}

			if err := bpf.ConvertKeyValue(key, value, &svcKey, &svcVal); err != nil {
				return nil, nil, err
			}

			return svcKey.ToNetwork(), svcVal.ToNetwork(), nil
		}).WithCache()
	Backend6Map = bpf.NewMap("cilium_lb6_backends",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Backend6Key{})),
		int(unsafe.Sizeof(Backend6Value{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			backendKey, backendVal := Backend6Key{}, Backend6Value{}

			if err := bpf.ConvertKeyValue(key, value, &backendKey, &backendVal); err != nil {
				return nil, nil, err
			}

			return &backendKey, backendVal.ToNetwork(), nil
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
	// RRSeq6MapV2 represents the BPF map for wrr sequences in IPv6 load balancer
	RRSeq6MapV2 = bpf.NewMap("cilium_lb6_rr_seq_v2",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Service6KeyV2{})),
		int(unsafe.Sizeof(RRSeqValue{})),
		maxFrontEnds,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			svcKey, svcVal := Service6KeyV2{}, RRSeqValue{}

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
func (s *Service6Value) GetPort() uint16             { return s.Port }
func (s *Service6Value) SetCount(count int)          { s.Count = uint16(count) }
func (s *Service6Value) GetCount() int               { return int(s.Count) }
func (s *Service6Value) SetRevNat(id int)            { s.RevNat = uint16(id) }
func (s *Service6Value) RevNatKey() RevNatKey        { return &RevNat6Key{s.RevNat} }
func (s *Service6Value) SetWeight(weight uint16)     { s.Weight = weight }
func (s *Service6Value) GetWeight() uint16           { return s.Weight }
func (s *Service6Value) IsIPv6() bool                { return true }

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

func (s *Service6Value) BackendAddrID() BackendAddrID {
	return BackendAddrID(fmt.Sprintf("[%s]:%d", s.Address, s.Port))
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

// Service6KeyV2 must match 'struct lb6_key_v2' in "bpf/lib/common.h".
type Service6KeyV2 struct {
	Address types.IPv6 `align:"address"`
	Port    uint16     `align:"dport"`
	Slave   uint16     `align:"slave"`
	Proto   uint8      `align:"proto"`
	Pad     uint8
}

func NewService6KeyV2(ip net.IP, port uint16, proto u8proto.U8proto, slave uint16) *Service6KeyV2 {
	key := Service6KeyV2{
		Port:  port,
		Proto: uint8(proto),
		Slave: slave,
	}

	copy(key.Address[:], ip.To16())

	return &key
}

func (k *Service6KeyV2) String() string {
	return fmt.Sprintf("[%s]:%d", k.Address, k.Port)
}

func (k *Service6KeyV2) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Service6KeyV2) NewValue() bpf.MapValue    { return &Service6ValueV2{} }
func (k *Service6KeyV2) IsIPv6() bool              { return true }
func (k *Service6KeyV2) Map() *bpf.Map             { return Service6MapV2 }
func (k *Service6KeyV2) RRMap() *bpf.Map           { return RRSeq6MapV2 }
func (k *Service6KeyV2) SetSlave(slave int)        { k.Slave = uint16(slave) }
func (k *Service6KeyV2) GetSlave() int             { return int(k.Slave) }
func (k *Service6KeyV2) GetAddress() net.IP        { return k.Address.DuplicateIP() }
func (k *Service6KeyV2) GetPort() uint16           { return k.Port }
func (k *Service6KeyV2) MapDelete() error          { return k.Map().Delete(k.ToNetwork()) }

func (k *Service6KeyV2) ToNetwork() ServiceKeyV2 {
	n := *k
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

// Service6ValueV2 must match 'struct lb6_service_v2' in "bpf/lib/common.h".
type Service6ValueV2 struct {
	Count     uint16 `align:"count"`
	BackendID uint16 `align:"backend_id"`
	RevNat    uint16 `align:"rev_nat_index"`
	Weight    uint16 `align:"weight"`
}

func NewService6ValueV2(count uint16, backendID uint16, revNat uint16, weight uint16) *Service6ValueV2 {
	svc := Service6ValueV2{
		Count:     count,
		BackendID: backendID,
		RevNat:    revNat,
		Weight:    weight,
	}

	return &svc
}

func (s *Service6ValueV2) String() string {
	return fmt.Sprintf("%d (%d)", s.BackendID, s.RevNat)
}

func (s *Service6ValueV2) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }

func (s *Service6ValueV2) SetCount(count int)      { s.Count = uint16(count) }
func (s *Service6ValueV2) GetCount() int           { return int(s.Count) }
func (s *Service6ValueV2) SetRevNat(id int)        { s.RevNat = uint16(id) }
func (s *Service6ValueV2) GetRevNat() int          { return int(s.RevNat) }
func (s *Service6ValueV2) SetWeight(weight uint16) { s.Weight = weight }
func (s *Service6ValueV2) GetWeight() uint16       { return s.Weight }
func (s *Service6ValueV2) SetBackendID(id uint16)  { s.BackendID = id }
func (s *Service6ValueV2) GetBackendID() uint16    { return s.BackendID }
func (s *Service6ValueV2) RevNatKey() RevNatKey    { return &RevNat6Key{s.RevNat} }

func (s *Service6ValueV2) ToNetwork() ServiceValueV2 {
	n := *s
	n.RevNat = byteorder.HostToNetwork(n.RevNat).(uint16)
	n.Weight = byteorder.HostToNetwork(n.Weight).(uint16)
	return &n
}

type Backend6Key struct {
	ID uint16
}

func NewBackend6Key(id uint16) *Backend6Key {
	return &Backend6Key{ID: id}
}

func (k *Backend6Key) String() string            { return fmt.Sprintf("%d", k.ID) }
func (k *Backend6Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Backend6Key) NewValue() bpf.MapValue    { return &Backend6Value{} }
func (k *Backend6Key) Map() *bpf.Map             { return Backend6Map }
func (k *Backend6Key) SetID(id uint16)           { k.ID = id }
func (k *Backend6Key) GetID() uint16             { return k.ID }

// Backend6Value must match 'struct lb6_backend' in "bpf/lib/common.h".
type Backend6Value struct {
	Address types.IPv6      `align:"address"`
	Port    uint16          `align:"port"`
	Proto   u8proto.U8proto `align:"proto"`
	Pad     uint8
}

func NewBackend6Value(ip net.IP, port uint16, proto u8proto.U8proto) (*Backend6Value, error) {
	ip6 := ip.To16()
	if ip6 == nil {
		return nil, fmt.Errorf("Not an IPv6 address")
	}

	val := Backend6Value{
		Port:  port,
		Proto: proto,
	}
	copy(val.Address[:], ip.To16())

	return &val, nil
}

func (v *Backend6Value) String() string {
	return fmt.Sprintf("%s://[%s]:%d", v.Proto, v.Address, v.Port)
}

func (v *Backend6Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (b *Backend6Value) GetAddress() net.IP { return b.Address.DuplicateIP() }
func (b *Backend6Value) GetPort() uint16    { return b.Port }

func (b *Backend6Value) BackendAddrID() BackendAddrID {
	return BackendAddrID(fmt.Sprintf("%s:%d", b.Address, b.Port))
}

func (v *Backend6Value) ToNetwork() BackendValue {
	n := *v
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

type Backend6 struct {
	Key   *Backend6Key
	Value *Backend6Value
}

func NewBackend6(id uint16, ip net.IP, port uint16, proto u8proto.U8proto) (*Backend6, error) {
	ip6 := ip.To16()
	if ip6 == nil {
		return nil, fmt.Errorf("Not an IPv6 address")
	}

	val, err := NewBackend6Value(ip, port, proto)
	if err != nil {
		return nil, err
	}

	return &Backend6{
		Key:   NewBackend6Key(id),
		Value: val,
	}, nil
}

func (b *Backend6) IsIPv6() bool           { return true }
func (b *Backend6) Map() *bpf.Map          { return Backend6Map }
func (b *Backend6) GetID() uint16          { return b.Key.GetID() }
func (b *Backend6) GetKey() bpf.MapKey     { return b.Key }
func (b *Backend6) GetValue() BackendValue { return b.Value }

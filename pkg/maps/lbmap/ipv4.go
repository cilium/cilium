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
	Service4Map = bpf.NewMap("cilium_lb4_services",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Service4Key{})),
		int(unsafe.Sizeof(Service4Value{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			svcKey, svcVal := Service4Key{}, Service4Value{}

			if err := bpf.ConvertKeyValue(key, value, &svcKey, &svcVal); err != nil {
				return nil, nil, err
			}

			return svcKey.ToNetwork(), svcVal.ToNetwork(), nil
		}).WithCache()
	Service4MapV2 = bpf.NewMap("cilium_lb4_services_v2",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Service4KeyV2{})),
		int(unsafe.Sizeof(Service4ValueV2{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			svcKey, svcVal := Service4KeyV2{}, Service4ValueV2{}

			if err := bpf.ConvertKeyValue(key, value, &svcKey, &svcVal); err != nil {
				return nil, nil, err
			}

			return svcKey.ToNetwork(), svcVal.ToNetwork(), nil
		}).WithCache()
	Backend4Map = bpf.NewMap("cilium_lb4_backends",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Backend4Key{})),
		int(unsafe.Sizeof(Backend4Value{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			backendKey, backendVal := Backend4Key{}, Backend4Value{}

			if err := bpf.ConvertKeyValue(key, value, &backendKey, &backendVal); err != nil {
				return nil, nil, err
			}

			return &backendKey, backendVal.ToNetwork(), nil
		}).WithCache()
	RevNat4Map = bpf.NewMap("cilium_lb4_reverse_nat",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(RevNat4Key{})),
		int(unsafe.Sizeof(RevNat4Value{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			var ukey uint16
			var revNat RevNat4Value

			if err := bpf.ConvertKeyValue(key, value, &ukey, &revNat); err != nil {
				return nil, nil, err
			}

			revKey := NewRevNat4Key(ukey)

			return revKey.ToNetwork(), revNat.ToNetwork(), nil
		}).WithCache()
	RRSeq4Map = bpf.NewMap("cilium_lb4_rr_seq",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Service4Key{})),
		int(unsafe.Sizeof(RRSeqValue{})),
		maxFrontEnds,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			svcKey, svcVal := Service4Key{}, RRSeqValue{}

			if err := bpf.ConvertKeyValue(key, value, &svcKey, &svcVal); err != nil {
				return nil, nil, err
			}

			return svcKey.ToNetwork(), &svcVal, nil
		}).WithCache()
	RRSeq4MapV2 = bpf.NewMap("cilium_lb4_rr_seq_v2",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Service4KeyV2{})),
		int(unsafe.Sizeof(RRSeqValue{})),
		maxFrontEnds,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			svcKey, rrSeqVal := Service4KeyV2{}, RRSeqValue{}

			if err := bpf.ConvertKeyValue(key, value, &svcKey, &rrSeqVal); err != nil {
				return nil, nil, err
			}

			return svcKey.ToNetwork(), &rrSeqVal, nil
		}).WithCache()
)

// Service4Key must match 'struct lb4_key' in "bpf/lib/common.h".
type Service4Key struct {
	Address types.IPv4 `align:"address"`
	Port    uint16     `align:"dport"`
	Slave   uint16     `align:"slave"`
}

func (k Service4Key) IsIPv6() bool               { return false }
func (k Service4Key) Map() *bpf.Map              { return Service4Map }
func (k Service4Key) RRMap() *bpf.Map            { return RRSeq4Map }
func (k Service4Key) NewValue() bpf.MapValue     { return &Service4Value{} }
func (k *Service4Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Service4Key) GetPort() uint16           { return k.Port }
func (k *Service4Key) SetPort(port uint16)       { k.Port = port }
func (k *Service4Key) SetBackend(backend int)    { k.Slave = uint16(backend) }
func (k *Service4Key) GetBackend() int           { return int(k.Slave) }

func (k *Service4Key) String() string {
	return fmt.Sprintf("%s:%d", k.Address, k.Port)
}

// ToNetwork converts Service4Key port to network byte order.
func (k *Service4Key) ToNetwork() ServiceKey {
	n := *k
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

// ToHost converts Service4Key port to network byte order.
func (k *Service4Key) ToHost() ServiceKey {
	n := *k
	n.Port = byteorder.NetworkToHost(n.Port).(uint16)
	return &n
}

func (k *Service4Key) MapDelete() error {
	return k.Map().Delete(k)
}

func NewService4Key(ip net.IP, port uint16, slave uint16) *Service4Key {
	key := Service4Key{
		Port:  port,
		Slave: slave,
	}

	copy(key.Address[:], ip.To4())

	return &key
}

func (k *Service4Key) RevNatValue() RevNatValue {
	return &RevNat4Value{
		Address: k.Address,
		Port:    k.Port,
	}
}

// Service4Value must match 'struct lb4_service' in "bpf/lib/common.h".
type Service4Value struct {
	Address types.IPv4 `align:"target"`
	Port    uint16     `align:"port"`
	Count   uint16     `align:"count"`
	RevNat  uint16     `align:"rev_nat_index"`
	Weight  uint16     `align:"weight"`
}

func NewService4Value(count uint16, target net.IP, port uint16, revNat uint16, weight uint16) *Service4Value {
	svc := Service4Value{
		Count:  count,
		RevNat: revNat,
		Port:   port,
		Weight: weight,
	}

	copy(svc.Address[:], target.To4())

	return &svc
}

func (s *Service4Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }
func (s *Service4Value) SetPort(port uint16)         { s.Port = port }
func (s *Service4Value) GetPort() uint16             { return s.Port }
func (s *Service4Value) SetCount(count int)          { s.Count = uint16(count) }
func (s *Service4Value) GetCount() int               { return int(s.Count) }
func (s *Service4Value) SetRevNat(id int)            { s.RevNat = uint16(id) }
func (s *Service4Value) SetWeight(weight uint16)     { s.Weight = weight }
func (s *Service4Value) GetWeight() uint16           { return s.Weight }
func (s *Service4Value) IsIPv6() bool                { return false }

func (s *Service4Value) SetAddress(ip net.IP) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("Not an IPv4 address")
	}
	copy(s.Address[:], ip4)
	return nil
}

// ToNetwork converts Service4Value to network byte order.
func (s *Service4Value) ToNetwork() ServiceValue {
	n := *s
	n.RevNat = byteorder.HostToNetwork(n.RevNat).(uint16)
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	n.Weight = byteorder.HostToNetwork(n.Weight).(uint16)
	return &n
}

// ToHost converts Service4Value to host byte order.
func (s *Service4Value) ToHost() ServiceValue {
	n := *s
	n.RevNat = byteorder.NetworkToHost(n.RevNat).(uint16)
	n.Port = byteorder.NetworkToHost(n.Port).(uint16)
	n.Weight = byteorder.NetworkToHost(n.Weight).(uint16)
	return &n
}

func (s *Service4Value) RevNatKey() RevNatKey {
	return &RevNat4Key{s.RevNat}
}

func (s *Service4Value) String() string {
	return fmt.Sprintf("%s:%d (%d)", s.Address, s.Port, s.RevNat)
}

func (s *Service4Value) BackendAddrID() BackendAddrID {
	return BackendAddrID(fmt.Sprintf("%s:%d", s.Address, s.Port))
}

type RevNat4Key struct {
	Key uint16
}

func NewRevNat4Key(value uint16) *RevNat4Key {
	return &RevNat4Key{value}
}

func (k *RevNat4Key) IsIPv6() bool              { return false }
func (k *RevNat4Key) Map() *bpf.Map             { return RevNat4Map }
func (k *RevNat4Key) NewValue() bpf.MapValue    { return &RevNat4Value{} }
func (k *RevNat4Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *RevNat4Key) String() string            { return fmt.Sprintf("%d", k.Key) }
func (k *RevNat4Key) GetKey() uint16            { return k.Key }

// ToNetwork converts RevNat4Key to network byte order.
func (k *RevNat4Key) ToNetwork() RevNatKey {
	n := *k
	n.Key = byteorder.HostToNetwork(n.Key).(uint16)
	return &n
}

type RevNat4Value struct {
	Address types.IPv4
	Port    uint16
}

func (v *RevNat4Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// ToNetwork converts RevNat4Value to network byte order.
func (v *RevNat4Value) ToNetwork() RevNatValue {
	n := *v
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

func (v *RevNat4Value) String() string {
	return fmt.Sprintf("%s:%d", v.Address, v.Port)
}

func NewRevNat4Value(ip net.IP, port uint16) *RevNat4Value {
	revNat := RevNat4Value{
		Port: port,
	}

	copy(revNat.Address[:], ip.To4())

	return &revNat
}

// Service4KeyV2 must match 'struct lb4_key_v2' in "bpf/lib/common.h".
type Service4KeyV2 struct {
	Address types.IPv4 `align:"address"`
	Port    uint16     `align:"dport"`
	Slave   uint16     `align:"slave"`
	Proto   uint8      `align:"proto"`
	Pad     uint8
}

func NewService4KeyV2(ip net.IP, port uint16, proto u8proto.U8proto, slave uint16) *Service4KeyV2 {
	key := Service4KeyV2{
		Port:  port,
		Proto: uint8(proto),
		Slave: slave,
	}

	copy(key.Address[:], ip.To4())

	return &key
}

func (k *Service4KeyV2) String() string {
	return fmt.Sprintf("%s:%d", k.Address, k.Port)
}

func (k *Service4KeyV2) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Service4KeyV2) NewValue() bpf.MapValue    { return &Service4ValueV2{} }
func (k *Service4KeyV2) IsIPv6() bool              { return false }
func (k *Service4KeyV2) Map() *bpf.Map             { return Service4MapV2 }
func (k *Service4KeyV2) RRMap() *bpf.Map           { return RRSeq4MapV2 }
func (k *Service4KeyV2) SetSlave(slave int)        { k.Slave = uint16(slave) }
func (k *Service4KeyV2) GetSlave() int             { return int(k.Slave) }
func (k *Service4KeyV2) GetAddress() net.IP        { return k.Address.DuplicateIP() }
func (k *Service4KeyV2) GetPort() uint16           { return k.Port }
func (k *Service4KeyV2) MapDelete() error          { return k.Map().Delete(k.ToNetwork()) }

func (k *Service4KeyV2) ToNetwork() ServiceKeyV2 {
	n := *k
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

// Service4ValueV2 must match 'struct lb4_service_v2' in "bpf/lib/common.h".
type Service4ValueV2 struct {
	Count     uint16 `align:"count"`
	BackendID uint16 `align:"backend_id"`
	RevNat    uint16 `align:"rev_nat_index"`
	Weight    uint16 `align:"weight"`
}

func NewService4ValueV2(count uint16, backendID uint16, revNat uint16, weight uint16) *Service4ValueV2 {
	svc := Service4ValueV2{
		Count:     count,
		BackendID: backendID,
		RevNat:    revNat,
		Weight:    weight,
	}

	return &svc
}

func (s *Service4ValueV2) String() string {
	return fmt.Sprintf("%d (%d)", s.BackendID, s.RevNat)
}

func (s *Service4ValueV2) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }

func (s *Service4ValueV2) SetCount(count int)      { s.Count = uint16(count) }
func (s *Service4ValueV2) GetCount() int           { return int(s.Count) }
func (s *Service4ValueV2) SetRevNat(id int)        { s.RevNat = uint16(id) }
func (s *Service4ValueV2) GetRevNat() int          { return int(s.RevNat) }
func (s *Service4ValueV2) SetWeight(weight uint16) { s.Weight = weight }
func (s *Service4ValueV2) GetWeight() uint16       { return s.Weight }
func (s *Service4ValueV2) SetBackendID(id uint16)  { s.BackendID = id }
func (s *Service4ValueV2) GetBackendID() uint16    { return s.BackendID }
func (s *Service4ValueV2) RevNatKey() RevNatKey    { return &RevNat4Key{s.RevNat} }

func (s *Service4ValueV2) ToNetwork() ServiceValueV2 {
	n := *s
	n.RevNat = byteorder.HostToNetwork(n.RevNat).(uint16)
	n.Weight = byteorder.HostToNetwork(n.Weight).(uint16)
	return &n
}

type Backend4Key struct {
	ID uint16
}

func NewBackend4Key(id uint16) *Backend4Key {
	return &Backend4Key{ID: id}
}

func (k *Backend4Key) String() string            { return fmt.Sprintf("%d", k.ID) }
func (k *Backend4Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Backend4Key) NewValue() bpf.MapValue    { return &Backend4Value{} }
func (k *Backend4Key) Map() *bpf.Map             { return Backend4Map }
func (k *Backend4Key) SetID(id uint16)           { k.ID = id }
func (k *Backend4Key) GetID() uint16             { return k.ID }

// Backend4Value must match 'struct lb4_backend' in "bpf/lib/common.h".
type Backend4Value struct {
	Address types.IPv4      `align:"address"`
	Port    uint16          `align:"port"`
	Proto   u8proto.U8proto `align:"proto"`
	Pad     uint8
}

func NewBackend4Value(ip net.IP, port uint16, proto u8proto.U8proto) (*Backend4Value, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("Not an IPv4 address")
	}

	val := Backend4Value{
		Port:  port,
		Proto: proto,
	}
	copy(val.Address[:], ip.To4())

	return &val, nil
}

func (v *Backend4Value) String() string {
	return fmt.Sprintf("%s://%s:%d", v.Proto, v.Address, v.Port)
}

func (v *Backend4Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (b *Backend4Value) GetAddress() net.IP { return b.Address.DuplicateIP() }
func (b *Backend4Value) GetPort() uint16    { return b.Port }

func (b *Backend4Value) BackendAddrID() BackendAddrID {
	return BackendAddrID(fmt.Sprintf("%s:%d", b.Address, b.Port))
}

func (v *Backend4Value) ToNetwork() BackendValue {
	n := *v
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

type Backend4 struct {
	Key   *Backend4Key
	Value *Backend4Value
}

func NewBackend4(id uint16, ip net.IP, port uint16, proto u8proto.U8proto) (*Backend4, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("Not an IPv4 address")
	}

	val, err := NewBackend4Value(ip, port, proto)
	if err != nil {
		return nil, err
	}

	return &Backend4{
		Key:   NewBackend4Key(id),
		Value: val,
	}, nil
}

func (b *Backend4) IsIPv6() bool           { return false }
func (b *Backend4) Map() *bpf.Map          { return Backend4Map }
func (b *Backend4) GetID() uint16          { return b.Key.GetID() }
func (b *Backend4) GetKey() bpf.MapKey     { return b.Key }
func (b *Backend4) GetValue() BackendValue { return b.Value }

// Copyright 2016-2020 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	// SockRevNat6MapName is the BPF map name.
	SockRevNat6MapName = "cilium_lb6_reverse_sk"

	// SockRevNat6MapSize is the maximum number of entries in the BPF map.
	SockRevNat6MapSize = 256 * 1024
)

var (
	Service6MapV2 = bpf.NewMap("cilium_lb6_services_v2",
		bpf.MapTypeHash,
		&Service6Key{},
		int(unsafe.Sizeof(Service6Key{})),
		&Service6Value{},
		int(unsafe.Sizeof(Service6Value{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte, mapKey bpf.MapKey, mapValue bpf.MapValue) (bpf.MapKey, bpf.MapValue, error) {
			svcKey, svcVal := mapKey.(*Service6Key), mapValue.(*Service6Value)

			if _, _, err := bpf.ConvertKeyValue(key, value, svcKey, svcVal); err != nil {
				return nil, nil, err
			}

			return svcKey.ToNetwork(), svcVal.ToNetwork(), nil
		}).WithCache()
	Backend6Map = bpf.NewMap("cilium_lb6_backends",
		bpf.MapTypeHash,
		&Backend6Key{},
		int(unsafe.Sizeof(Backend6Key{})),
		&Backend6Value{},
		int(unsafe.Sizeof(Backend6Value{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte, mapKey bpf.MapKey, mapValue bpf.MapValue) (bpf.MapKey, bpf.MapValue, error) {
			backendVal := mapValue.(*Backend6Value)

			if _, _, err := bpf.ConvertKeyValue(key, value, mapKey, backendVal); err != nil {
				return nil, nil, err
			}

			return mapKey, backendVal.ToNetwork(), nil
		}).WithCache()
	// RevNat6Map represents the BPF map for reverse NAT in IPv6 load balancer
	RevNat6Map = bpf.NewMap("cilium_lb6_reverse_nat",
		bpf.MapTypeHash,
		&RevNat6Key{},
		int(unsafe.Sizeof(RevNat6Key{})),
		&RevNat6Value{},
		int(unsafe.Sizeof(RevNat6Value{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte, mapKey bpf.MapKey, mapValue bpf.MapValue) (bpf.MapKey, bpf.MapValue, error) {
			revKey, revNat := mapKey.(*RevNat6Key), mapValue.(*RevNat6Value)

			if _, _, err := bpf.ConvertKeyValue(key, value, revKey, revNat); err != nil {
				return nil, nil, err
			}

			return revKey.ToNetwork(), revNat.ToNetwork(), nil
		}).WithCache()
)

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type RevNat6Key struct {
	Key uint16
}

func NewRevNat6Key(value uint16) *RevNat6Key {
	return &RevNat6Key{value}
}

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

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type RevNat6Value struct {
	Address types.IPv6 `align:"address"`
	Port    uint16     `align:"port"`
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

// Service6Key must match 'struct lb6_key_v2' in "bpf/lib/common.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Service6Key struct {
	Address types.IPv6 `align:"address"`
	Port    uint16     `align:"dport"`
	Slave   uint16     `align:"slave"`
	Proto   uint8      `align:"proto"`
	Pad     pad3uint8  `align:"pad"`
}

func NewService6Key(ip net.IP, port uint16, proto u8proto.U8proto, slave uint16) *Service6Key {
	key := Service6Key{
		Port:  port,
		Proto: uint8(proto),
		Slave: slave,
	}

	copy(key.Address[:], ip.To16())

	return &key
}

func (k *Service6Key) String() string {
	return fmt.Sprintf("[%s]:%d", k.Address, k.Port)
}

func (k *Service6Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Service6Key) NewValue() bpf.MapValue    { return &Service6Value{} }
func (k *Service6Key) IsIPv6() bool              { return true }
func (k *Service6Key) Map() *bpf.Map             { return Service6MapV2 }
func (k *Service6Key) SetSlave(slave int)        { k.Slave = uint16(slave) }
func (k *Service6Key) GetSlave() int             { return int(k.Slave) }
func (k *Service6Key) GetAddress() net.IP        { return k.Address.IP() }
func (k *Service6Key) GetPort() uint16           { return k.Port }
func (k *Service6Key) MapDelete() error          { return k.Map().Delete(k.ToNetwork()) }

func (k *Service6Key) RevNatValue() RevNatValue {
	return &RevNat6Value{
		Address: k.Address,
		Port:    k.Port,
	}
}

func (k *Service6Key) ToNetwork() ServiceKey {
	n := *k
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

// Service6Value must match 'struct lb6_service_v2' in "bpf/lib/common.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Service6Value struct {
	BackendID uint32 `align:"backend_id"`
	Count     uint16 `align:"count"`
	RevNat    uint16 `align:"rev_nat_index"`
	Flags     uint8
	Pad       pad3uint8 `align:"pad"`
}

func NewService6Value(count uint16, backendID loadbalancer.BackendID, revNat uint16) *Service6Value {
	svc := Service6Value{
		Count:     count,
		BackendID: uint32(backendID),
		RevNat:    revNat,
	}

	return &svc
}

func (s *Service6Value) String() string {
	return fmt.Sprintf("%d (%d) [FLAGS: 0x%x]", s.BackendID, s.RevNat, s.Flags)
}

func (s *Service6Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }

func (s *Service6Value) SetCount(count int)   { s.Count = uint16(count) }
func (s *Service6Value) GetCount() int        { return int(s.Count) }
func (s *Service6Value) SetRevNat(id int)     { s.RevNat = uint16(id) }
func (s *Service6Value) GetRevNat() int       { return int(s.RevNat) }
func (s *Service6Value) RevNatKey() RevNatKey { return &RevNat6Key{s.RevNat} }
func (s *Service6Value) SetFlags(flags uint8) { s.Flags = flags }
func (s *Service6Value) GetFlags() uint8      { return s.Flags }

func (s *Service6Value) SetBackendID(id loadbalancer.BackendID) {
	s.BackendID = uint32(id)
}
func (s *Service6Value) GetBackendID() loadbalancer.BackendID {
	return loadbalancer.BackendID(s.BackendID)
}

func (s *Service6Value) ToNetwork() ServiceValue {
	n := *s
	n.RevNat = byteorder.HostToNetwork(n.RevNat).(uint16)
	return &n
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Backend6Key struct {
	ID loadbalancer.BackendID
}

func NewBackend6Key(id loadbalancer.BackendID) *Backend6Key {
	return &Backend6Key{ID: id}
}

func (k *Backend6Key) String() string                  { return fmt.Sprintf("%d", k.ID) }
func (k *Backend6Key) GetKeyPtr() unsafe.Pointer       { return unsafe.Pointer(k) }
func (k *Backend6Key) NewValue() bpf.MapValue          { return &Backend6Value{} }
func (k *Backend6Key) Map() *bpf.Map                   { return Backend6Map }
func (k *Backend6Key) SetID(id loadbalancer.BackendID) { k.ID = id }
func (k *Backend6Key) GetID() loadbalancer.BackendID   { return k.ID }

// Backend6Value must match 'struct lb6_backend' in "bpf/lib/common.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Backend6Value struct {
	Address types.IPv6      `align:"address"`
	Port    uint16          `align:"port"`
	Proto   u8proto.U8proto `align:"proto"`
	Pad     uint8           `align:"pad"`
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

func (b *Backend6Value) GetAddress() net.IP { return b.Address.IP() }
func (b *Backend6Value) GetPort() uint16    { return b.Port }

func (v *Backend6Value) ToNetwork() BackendValue {
	n := *v
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

type Backend6 struct {
	Key   *Backend6Key
	Value *Backend6Value
}

func NewBackend6(id loadbalancer.BackendID, ip net.IP, port uint16, proto u8proto.U8proto) (*Backend6, error) {
	val, err := NewBackend6Value(ip, port, proto)
	if err != nil {
		return nil, err
	}

	return &Backend6{
		Key:   NewBackend6Key(id),
		Value: val,
	}, nil
}

func (b *Backend6) Map() *bpf.Map          { return Backend6Map }
func (b *Backend6) GetKey() BackendKey     { return b.Key }
func (b *Backend6) GetValue() BackendValue { return b.Value }

// SockRevNat6Key is the tuple with address, port and cookie used as key in
// the reverse NAT sock map.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type SockRevNat6Key struct {
	cookie  uint64
	address types.IPv6
	port    int16
	pad     int16
}

// SockRevNat6Value is an entry in the reverse NAT sock map.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type SockRevNat6Value struct {
	address     types.IPv6
	port        int16
	revNatIndex uint16
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *SockRevNat6Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *SockRevNat6Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human readable string format.
func (k *SockRevNat6Key) String() string {
	return fmt.Sprintf("%s:%d, %d", k.address, k.port, k.cookie)
}

// String converts the value into a human readable string format.
func (v *SockRevNat6Value) String() string {
	return fmt.Sprintf("%s:%d, %d", v.address, v.port, v.revNatIndex)
}

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k SockRevNat6Key) NewValue() bpf.MapValue { return &SockRevNat6Value{} }

// CreateSockRevNat6Map creates the reverse NAT sock map.
func CreateSockRevNat6Map() error {
	sockRevNat6Map := bpf.NewMap(SockRevNat6MapName,
		bpf.MapTypeLRUHash,
		&SockRevNat6Key{},
		int(unsafe.Sizeof(SockRevNat6Key{})),
		&SockRevNat6Value{},
		int(unsafe.Sizeof(SockRevNat6Value{})),
		SockRevNat6MapSize,
		0,
		0,
		bpf.ConvertKeyValue,
	)
	_, err := sockRevNat6Map.Create()
	return err
}

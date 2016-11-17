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
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/bpf"
	"github.com/cilium/cilium/common/types"
)

var (
	Service4Map = bpf.NewMap(common.BPFCiliumMaps+"/cilium_lb4_services",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Service4Key{})),
		int(unsafe.Sizeof(Service4Value{})),
		maxEntries)
	RevNat4Map = bpf.NewMap(common.BPFCiliumMaps+"/cilium_lb4_reverse_nat",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(RevNat4Key{})),
		int(unsafe.Sizeof(RevNat4Value{})),
		maxEntries)
)

// Must match 'struct lb4_key' in "bpf/lib/common.h"
type Service4Key struct {
	Address types.IPv4
	Port    uint16
	Slave   uint16
}

func (k Service4Key) IsIPv6() bool               { return false }
func (k Service4Key) Map() *bpf.Map              { return Service4Map }
func (k Service4Key) NewValue() bpf.MapValue     { return &Service4Value{} }
func (k *Service4Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Service4Key) GetPort() uint16           { return k.Port }
func (k *Service4Key) SetPort(port uint16)       { k.Port = port }
func (k *Service4Key) SetBackend(backend int)    { k.Slave = uint16(backend) }
func (k *Service4Key) GetBackend() int           { return int(k.Slave) }

func (k *Service4Key) String() string {
	return fmt.Sprintf("%s:%d", k.Address, k.Port)
}

func (k *Service4Key) Convert() ServiceKey {
	n := *k
	n.Port = common.Swab16(n.Port)
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

// Must match 'struct lb4_service' in "bpf/lib/common.h"
type Service4Value struct {
	Address types.IPv4
	Port    uint16
	Count   uint16
	RevNat  uint16
}

func NewService4Value(count uint16, target net.IP, port uint16, revNat uint16) *Service4Value {
	svc := Service4Value{
		Count:  count,
		RevNat: revNat,
		Port:   port,
	}

	copy(svc.Address[:], target.To4())

	return &svc
}

func (s *Service4Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }
func (s *Service4Value) SetPort(port uint16)         { s.Port = port }
func (s *Service4Value) SetCount(count int)          { s.Count = uint16(count) }
func (s *Service4Value) GetCount() int               { return int(s.Count) }
func (s *Service4Value) SetRevNat(id int)            { s.RevNat = uint16(id) }
func (s *Service4Value) SetAddress(ip net.IP) error {
	if ip4 := ip.To4(); ip4 == nil {
		return fmt.Errorf("Not an IPv4 address")
	} else {
		copy(s.Address[:], ip4)
		return nil
	}
}

func (v *Service4Value) Convert() ServiceValue {
	n := *v
	n.RevNat = common.Swab16(n.RevNat)
	n.Port = common.Swab16(n.Port)
	return &n
}

func (v *Service4Value) RevNatKey() RevNatKey {
	return &RevNat4Key{v.RevNat}
}

func (v *Service4Value) String() string {
	return fmt.Sprintf("%s:%d (%d)", v.Address, v.Port, v.RevNat)
}

func Service4DumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	keyBuf := bytes.NewBuffer(key)
	valueBuf := bytes.NewBuffer(value)
	svcKey := Service4Key{}
	svcVal := Service4Value{}

	if err := binary.Read(keyBuf, binary.LittleEndian, &svcKey); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert key: %s\n", err)
	}

	if err := binary.Read(valueBuf, binary.LittleEndian, &svcVal); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert key: %s\n", err)
	}

	return svcKey.Convert(), svcVal.Convert(), nil
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

func (k *RevNat4Key) Convert() RevNatKey {
	n := *k
	n.Key = common.Swab16(n.Key)
	return &n
}

type RevNat4Value struct {
	Address types.IPv4
	Port    uint16
}

func (v *RevNat4Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (v *RevNat4Value) Convert() RevNatValue {
	n := *v
	n.Port = common.Swab16(n.Port)
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

func RevNat4DumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	var revNat RevNat4Value
	var ukey uint16

	keyBuf := bytes.NewBuffer(key)
	valueBuf := bytes.NewBuffer(value)

	if err := binary.Read(keyBuf, binary.LittleEndian, &ukey); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert key: %s\n", err)
	}
	revKey := NewRevNat4Key(ukey)

	if err := binary.Read(valueBuf, binary.LittleEndian, &revNat); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert value: %s\n", err)
	}

	return revKey.Convert(), revNat.Convert(), nil
}

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
	Service6Map = bpf.NewMap(common.BPFCiliumMaps+"/cilium_lb6_services",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(Service6Key{})),
		int(unsafe.Sizeof(Service6Value{})),
		maxEntries)
	RevNat6Map = bpf.NewMap(common.BPFCiliumMaps+"/cilium_lb6_reverse_nat",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(RevNat6Key(0))),
		int(unsafe.Sizeof(RevNat6Value{})),
		maxEntries)
)

// Must match 'struct lb6_key' in "bpf/lib/common.h"
type Service6Key struct {
	Address types.IPv6
	Port    uint16
	Slave   uint16
}

func NewService6Key(ip net.IP, port uint16, slave uint16) *Service6Key {
	key := Service6Key{
		Port:  common.Swab16(port),
		Slave: slave,
	}

	copy(key.Address[:], ip.To16())

	return &key
}

func (k Service6Key) IsIPv6() bool           { return true }
func (k Service6Key) Map() *bpf.Map          { return Service6Map }
func (k Service6Key) NewValue() bpf.MapValue { return &Service6Value{} }

func (k Service6Key) GetKeyPtr() unsafe.Pointer {
	return unsafe.Pointer(&k)
}

func (k *Service6Key) RevNatValue() RevNatValue {
	return &RevNat6Value{
		Address: k.Address,
		Port:    k.Port,
	}
}

// Must match 'struct lb6_service' in "bpf/lib/common.h"
type Service6Value struct {
	Address types.IPv6
	Port    uint16
	Count   uint16
	RevNat  uint16
}

func NewService6Value(count uint16, target net.IP, port uint16, revNat uint16) *Service6Value {
	svc := Service6Value{
		Count:  count,
		Port:   common.Swab16(port),
		RevNat: common.Swab16(revNat),
	}

	copy(svc.Address[:], target.To16())

	return &svc
}

func (s Service6Value) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(&s)
}

func (v *Service6Value) RevNatKey() RevNatKey {
	return RevNat6Key(v.RevNat)
}

func Service6DumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	keyBuf := bytes.NewBuffer(key)
	valueBuf := bytes.NewBuffer(value)
	svcKey := Service6Key{}
	svcVal := Service6Value{}

	if err := binary.Read(keyBuf, binary.LittleEndian, &svcKey); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert key: %s\n", err)
	}

	svcKey.Port = common.Swab16(svcKey.Port)

	if err := binary.Read(valueBuf, binary.LittleEndian, &svcVal); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert value: %s\n", err)
	}

	svcVal.Port = common.Swab16(svcVal.Port)
	svcVal.RevNat = common.Swab16(svcVal.RevNat)

	return &svcKey, &svcVal, nil
}

type RevNat6Key uint16

func NewRevNat6Key(value uint16) RevNat6Key {
	return RevNat6Key(common.Swab16(value))
}

func (k RevNat6Key) IsIPv6() bool           { return true }
func (k RevNat6Key) Map() *bpf.Map          { return RevNat6Map }
func (k RevNat6Key) NewValue() bpf.MapValue { return &RevNat6Value{} }
func (k RevNat6Key) GetKeyPtr() unsafe.Pointer {
	return unsafe.Pointer(&k)
}

type RevNat6Value struct {
	Address types.IPv6
	Port    uint16
}

func NewRevNat6Value(ip net.IP, port uint16) *RevNat6Value {
	revNat := RevNat6Value{
		Port: common.Swab16(port),
	}

	copy(revNat.Address[:], ip.To16())

	return &revNat
}

func (k RevNat6Value) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(&k)
}

func RevNat6DumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	var revNat RevNat6Value
	var ukey uint16

	keyBuf := bytes.NewBuffer(key)
	valueBuf := bytes.NewBuffer(value)

	if err := binary.Read(keyBuf, binary.LittleEndian, &ukey); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert key: %s\n", err)
	}
	revKey := NewRevNat6Key(ukey)

	if err := binary.Read(valueBuf, binary.LittleEndian, &revNat); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert value: %s\n", err)
	}

	revNat.Port = common.Swab16(revNat.Port)

	return &revKey, &revNat, nil
}

// Copyright 2016-2021 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	// HealthProbe6MapName is the health datapath map name
	HealthProbe6MapName = "cilium_lb6_health"

	// SockRevNat6MapName is the BPF map name.
	SockRevNat6MapName = "cilium_lb6_reverse_sk"

	// SockRevNat6MapSize is the maximum number of entries in the BPF map.
	SockRevNat6MapSize = 256 * 1024

	// Service6MapV2Name is the name of the IPv6 LB Services v2 BPF map.
	Service6MapV2Name = "cilium_lb6_services_v2"
	// Backend6MapName is the name of the IPv6 LB backends BPF map.
	Backend6MapName = "cilium_lb6_backends"
	// RevNat6MapName is the name of the IPv6 LB reverse NAT BPF map.
	RevNat6MapName = "cilium_lb6_reverse_nat"
)

var (
	// MaxSockRevNat6MapEntries is the maximum number of entries in the BPF
	// map. It is set by Init(), but unit tests use the initial value below.
	MaxSockRevNat6MapEntries = SockRevNat6MapSize

	// The following BPF maps are initialized in initSVC().

	// Service6MapV2 is the IPv6 LB Services v2 BPF map.
	Service6MapV2 *bpf.Map
	// Backend6Map is the IPv6 LB backends BPF map.
	Backend6Map *bpf.Map
	// RevNat6Map is the IPv6 LB reverse NAT BPF map.
	RevNat6Map *bpf.Map
)

// The compile-time check for whether the structs implement the interfaces
var _ RevNatKey = (*RevNat6Key)(nil)
var _ RevNatValue = (*RevNat6Value)(nil)
var _ ServiceKey = (*Service6Key)(nil)
var _ ServiceValue = (*Service6Value)(nil)
var _ BackendKey = (*Backend6Key)(nil)
var _ BackendValue = (*Backend6Value)(nil)
var _ Backend = (*Backend6)(nil)

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
func (v *RevNat6Key) String() string            { return fmt.Sprintf("%d", v.ToHost().(*RevNat6Key).Key) }
func (v *RevNat6Key) GetKey() uint16            { return v.Key }

// ToNetwork converts RevNat6Key to network byte order.
func (v *RevNat6Key) ToNetwork() RevNatKey {
	n := *v
	n.Key = byteorder.HostToNetwork(n.Key).(uint16)
	return &n
}

// ToNetwork converts RevNat6Key to host byte order.
func (v *RevNat6Key) ToHost() RevNatKey {
	h := *v
	h.Key = byteorder.NetworkToHost(h.Key).(uint16)
	return &h
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type RevNat6Value struct {
	Address types.IPv6 `align:"address"`
	Port    uint16     `align:"port"`
}

func (v *RevNat6Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (v *RevNat6Value) String() string {
	vHost := v.ToHost().(*RevNat6Value)
	return net.JoinHostPort(vHost.Address.String(), fmt.Sprintf("%d", vHost.Port))
}

// ToNetwork converts RevNat6Value to network byte order.
func (v *RevNat6Value) ToNetwork() RevNatValue {
	n := *v
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

// ToNetwork converts RevNat6Value to Host byte order.
func (v *RevNat6Value) ToHost() RevNatValue {
	h := *v
	h.Port = byteorder.NetworkToHost(h.Port).(uint16)
	return &h
}

// Service6Key must match 'struct lb6_key_v2' in "bpf/lib/common.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Service6Key struct {
	Address     types.IPv6 `align:"address"`
	Port        uint16     `align:"dport"`
	BackendSlot uint16     `align:"backend_slot"`
	Proto       uint8      `align:"proto"`
	Scope       uint8      `align:"scope"`
	Pad         pad2uint8  `align:"pad"`
}

func NewService6Key(ip net.IP, port uint16, proto u8proto.U8proto, scope uint8, slot uint16) *Service6Key {
	key := Service6Key{
		Port:        port,
		Proto:       uint8(proto),
		Scope:       scope,
		BackendSlot: slot,
	}

	copy(key.Address[:], ip.To16())

	return &key
}

func (k *Service6Key) String() string {
	return serviceKey(
		k.Address.String(),
		k.Port,
		k.GetProtocol(),
		k.Scope == loadbalancer.ScopeInternal,
	)
}

func (k *Service6Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Service6Key) NewValue() bpf.MapValue    { return &Service6Value{} }
func (k *Service6Key) IsIPv6() bool              { return true }
func (k *Service6Key) IsSurrogate() bool         { return k.GetAddress().IsUnspecified() }
func (k *Service6Key) Map() *bpf.Map             { return Service6MapV2 }
func (k *Service6Key) SetBackendSlot(slot int)   { k.BackendSlot = uint16(slot) }
func (k *Service6Key) GetBackendSlot() int       { return int(k.BackendSlot) }
func (k *Service6Key) SetScope(scope uint8)      { k.Scope = scope }
func (k *Service6Key) GetScope() uint8           { return k.Scope }
func (k *Service6Key) GetAddress() net.IP        { return k.Address.IP() }
func (k *Service6Key) GetPort() uint16           { return k.Port }
func (k *Service6Key) GetProtocol() uint8        { return k.Proto }
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

// ToHost converts Service6Key to host byte order.
func (k *Service6Key) ToHost() ServiceKey {
	h := *k
	h.Port = byteorder.NetworkToHost(h.Port).(uint16)
	return &h
}

// Service6Value must match 'struct lb6_service_v2' in "bpf/lib/common.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Service6Value struct {
	BackendID uint32    `align:"backend_id"`
	Count     uint16    `align:"count"`
	RevNat    uint16    `align:"rev_nat_index"`
	Flags     uint8     `align:"flags"`
	Flags2    uint8     `align:"flags2"`
	Pad       pad2uint8 `align:"pad"`
}

func (s *Service6Value) String() string {
	sHost := s.ToHost().(*Service6Value)
	return fmt.Sprintf("%d (%d) [FLAGS: 0x%x]", sHost.BackendID, sHost.RevNat, sHost.Flags)
}

func (s *Service6Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }

func (s *Service6Value) SetCount(count int)   { s.Count = uint16(count) }
func (s *Service6Value) GetCount() int        { return int(s.Count) }
func (s *Service6Value) SetRevNat(id int)     { s.RevNat = uint16(id) }
func (s *Service6Value) GetRevNat() int       { return int(s.RevNat) }
func (s *Service6Value) RevNatKey() RevNatKey { return &RevNat6Key{s.RevNat} }
func (s *Service6Value) SetFlags(flags uint16) {
	s.Flags = uint8(flags & 0xff)
	s.Flags2 = uint8(flags >> 8)
}

func (s *Service6Value) GetFlags() uint16 {
	return (uint16(s.Flags2) << 8) | uint16(s.Flags)
}

func (s *Service6Value) SetSessionAffinityTimeoutSec(t uint32) {
	// See (* Service4Value).SetSessionAffinityTimeoutSec() for comment
	s.BackendID = t
}

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

// ToHost converts Service6Value to host byte order.
func (s *Service6Value) ToHost() ServiceValue {
	h := *s
	h.RevNat = byteorder.NetworkToHost(h.RevNat).(uint16)
	return &h
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
	vHost := v.ToHost().(*Backend6Value)
	return fmt.Sprintf("%s://[%s]:%d", vHost.Proto, vHost.Address, vHost.Port)
}

func (v *Backend6Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (b *Backend6Value) GetAddress() net.IP { return b.Address.IP() }
func (b *Backend6Value) GetPort() uint16    { return b.Port }
func (b *Backend6Value) GetProtocol() uint8 { return uint8(b.Proto) }

func (v *Backend6Value) ToNetwork() BackendValue {
	n := *v
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

// ToHost converts Backend6Value to host byte order.
func (v *Backend6Value) ToHost() BackendValue {
	h := *v
	h.Port = byteorder.NetworkToHost(h.Port).(uint16)
	return &h
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
	cookie  uint64     `align:"cookie"`
	address types.IPv6 `align:"address"`
	port    int16      `align:"port"`
	pad     int16      `align:"pad"`
}

// SizeofSockRevNat6Key is the size of type SockRevNat6Key.
const SizeofSockRevNat6Key = int(unsafe.Sizeof(SockRevNat6Key{}))

// SockRevNat6Value is an entry in the reverse NAT sock map.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type SockRevNat6Value struct {
	address     types.IPv6 `align:"address"`
	port        int16      `align:"port"`
	revNatIndex uint16     `align:"rev_nat_index"`
}

// SizeofSockRevNat6Value is the size of type SockRevNat6Value.
const SizeofSockRevNat6Value = int(unsafe.Sizeof(SockRevNat6Value{}))

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *SockRevNat6Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *SockRevNat6Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human readable string format.
func (k *SockRevNat6Key) String() string {
	return fmt.Sprintf("[%s]:%d, %d", k.address, k.port, k.cookie)
}

// String converts the value into a human readable string format.
func (v *SockRevNat6Value) String() string {
	return fmt.Sprintf("[%s]:%d, %d", v.address, v.port, v.revNatIndex)
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
		MaxSockRevNat6MapEntries,
		0,
		0,
		bpf.ConvertKeyValue,
	).WithPressureMetric()
	_, err := sockRevNat6Map.Create()
	return err
}

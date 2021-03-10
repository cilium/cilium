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
	// HealthProbe4MapName is the health datapath map name
	HealthProbe4MapName = "cilium_lb4_health"

	// SockRevNat4MapName is the BPF map name.
	SockRevNat4MapName = "cilium_lb4_reverse_sk"

	// SockRevNat4MapSize is the maximum number of entries in the BPF map.
	SockRevNat4MapSize = 256 * 1024

	// Service4MapV2Name is the name of the IPv4 LB Services v2 BPF map.
	Service4MapV2Name = "cilium_lb4_services_v2"
	// Backend4MapName is the name of the IPv4 LB backends BPF map.
	Backend4MapName = "cilium_lb4_backends"
	// RevNat4MapName is the name of the IPv4 LB reverse NAT BPF map.
	RevNat4MapName = "cilium_lb4_reverse_nat"
)

var (
	// MaxSockRevNat4MapEntries is the maximum number of entries in the BPF
	// map. It is set by Init(), but unit tests use the initial value below.
	MaxSockRevNat4MapEntries = SockRevNat4MapSize

	// The following BPF maps are initialized in initSVC().

	// Service4MapV2 is the IPv4 LB Services v2 BPF map.
	Service4MapV2 *bpf.Map
	// Backend4Map is the IPv4 LB backends BPF map.
	Backend4Map *bpf.Map
	// RevNat4Map is the IPv4 LB reverse NAT BPF map.
	RevNat4Map *bpf.Map
)

// initSVC constructs the IPv4 & IPv6 LB BPF maps used for Services. The maps
// have their maximum entries configured. Note this does not create or open the
// maps; it simply constructs the objects.
func initSVC(params InitParams) {
	if params.IPv4 {
		Service4MapV2 = bpf.NewMap(Service4MapV2Name,
			bpf.MapTypeHash,
			&Service4Key{},
			int(unsafe.Sizeof(Service4Key{})),
			&Service4Value{},
			int(unsafe.Sizeof(Service4Value{})),
			MaxEntries,
			0, 0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric()
		Backend4Map = bpf.NewMap(Backend4MapName,
			bpf.MapTypeHash,
			&Backend4Key{},
			int(unsafe.Sizeof(Backend4Key{})),
			&Backend4Value{},
			int(unsafe.Sizeof(Backend4Value{})),
			MaxEntries,
			0, 0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric()
		RevNat4Map = bpf.NewMap(RevNat4MapName,
			bpf.MapTypeHash,
			&RevNat4Key{},
			int(unsafe.Sizeof(RevNat4Key{})),
			&RevNat4Value{},
			int(unsafe.Sizeof(RevNat4Value{})),
			MaxEntries,
			0, 0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric()
	}

	if params.IPv6 {
		Service6MapV2 = bpf.NewMap(Service6MapV2Name,
			bpf.MapTypeHash,
			&Service6Key{},
			int(unsafe.Sizeof(Service6Key{})),
			&Service6Value{},
			int(unsafe.Sizeof(Service6Value{})),
			MaxEntries,
			0, 0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric()
		Backend6Map = bpf.NewMap(Backend6MapName,
			bpf.MapTypeHash,
			&Backend6Key{},
			int(unsafe.Sizeof(Backend6Key{})),
			&Backend6Value{},
			int(unsafe.Sizeof(Backend6Value{})),
			MaxEntries,
			0, 0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric()
		RevNat6Map = bpf.NewMap(RevNat6MapName,
			bpf.MapTypeHash,
			&RevNat6Key{},
			int(unsafe.Sizeof(RevNat6Key{})),
			&RevNat6Value{},
			int(unsafe.Sizeof(RevNat6Value{})),
			MaxEntries,
			0, 0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric()
	}
}

// The compile-time check for whether the structs implement the interfaces
var _ RevNatKey = (*RevNat4Key)(nil)
var _ RevNatValue = (*RevNat4Value)(nil)
var _ ServiceKey = (*Service4Key)(nil)
var _ ServiceValue = (*Service4Value)(nil)
var _ BackendKey = (*Backend4Key)(nil)
var _ BackendValue = (*Backend4Value)(nil)
var _ Backend = (*Backend4)(nil)

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type RevNat4Key struct {
	Key uint16
}

func NewRevNat4Key(value uint16) *RevNat4Key {
	return &RevNat4Key{value}
}

func (k *RevNat4Key) Map() *bpf.Map             { return RevNat4Map }
func (k *RevNat4Key) NewValue() bpf.MapValue    { return &RevNat4Value{} }
func (k *RevNat4Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *RevNat4Key) String() string            { return fmt.Sprintf("%d", k.ToHost().(*RevNat4Key).Key) }
func (k *RevNat4Key) GetKey() uint16            { return k.Key }

// ToNetwork converts RevNat4Key to network byte order.
func (k *RevNat4Key) ToNetwork() RevNatKey {
	n := *k
	n.Key = byteorder.HostToNetwork(n.Key).(uint16)
	return &n
}

// ToHost converts RevNat4Key to host byte order.
func (k *RevNat4Key) ToHost() RevNatKey {
	h := *k
	h.Key = byteorder.NetworkToHost(h.Key).(uint16)
	return &h
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type RevNat4Value struct {
	Address types.IPv4 `align:"address"`
	Port    uint16     `align:"port"`
}

func (v *RevNat4Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// ToNetwork converts RevNat4Value to network byte order.
func (v *RevNat4Value) ToNetwork() RevNatValue {
	n := *v
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

// ToHost converts RevNat4Value to host byte order.
func (k *RevNat4Value) ToHost() RevNatValue {
	h := *k
	h.Port = byteorder.NetworkToHost(h.Port).(uint16)
	return &h
}

func (v *RevNat4Value) String() string {
	vHost := v.ToHost().(*RevNat4Value)
	return net.JoinHostPort(vHost.Address.String(), fmt.Sprintf("%d", vHost.Port))
}

type pad2uint8 [2]uint8

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *pad2uint8) DeepCopyInto(out *pad2uint8) {
	copy(out[:], in[:])
	return
}

// Service4Key must match 'struct lb4_key_v2' in "bpf/lib/common.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Service4Key struct {
	Address     types.IPv4 `align:"address"`
	Port        uint16     `align:"dport"`
	BackendSlot uint16     `align:"backend_slot"`
	Proto       uint8      `align:"proto"`
	Scope       uint8      `align:"scope"`
	Pad         pad2uint8  `align:"pad"`
}

func NewService4Key(ip net.IP, port uint16, proto u8proto.U8proto, scope uint8, slot uint16) *Service4Key {
	key := Service4Key{
		Port:        port,
		Proto:       uint8(proto),
		Scope:       scope,
		BackendSlot: slot,
	}

	copy(key.Address[:], ip.To4())

	return &key
}

func (k *Service4Key) String() string {
	return serviceKey(
		k.Address.String(),
		k.Port,
		k.GetProtocol(),
		k.Scope == loadbalancer.ScopeInternal,
	)
}

func serviceKey(address string, port uint16, protocol uint8, internal bool) string {
	a := net.JoinHostPort(address, fmt.Sprintf("%d", port))

	p, err := u8proto.FromNumber(protocol)
	if err != nil {
		p = u8proto.ANY
	}

	var i string
	if internal {
		i = "/i"
	}

	return fmt.Sprintf("%s/%s%s", a, p, i)
}

func (k *Service4Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Service4Key) NewValue() bpf.MapValue    { return &Service4Value{} }
func (k *Service4Key) IsIPv6() bool              { return false }
func (k *Service4Key) IsSurrogate() bool         { return k.GetAddress().IsUnspecified() }
func (k *Service4Key) Map() *bpf.Map             { return Service4MapV2 }
func (k *Service4Key) SetBackendSlot(slot int)   { k.BackendSlot = uint16(slot) }
func (k *Service4Key) GetBackendSlot() int       { return int(k.BackendSlot) }
func (k *Service4Key) SetScope(scope uint8)      { k.Scope = scope }
func (k *Service4Key) GetScope() uint8           { return k.Scope }
func (k *Service4Key) GetAddress() net.IP        { return k.Address.IP() }
func (k *Service4Key) GetPort() uint16           { return k.Port }
func (k *Service4Key) GetProtocol() uint8        { return k.Proto }
func (k *Service4Key) MapDelete() error          { return k.Map().Delete(k.ToNetwork()) }

func (k *Service4Key) RevNatValue() RevNatValue {
	return &RevNat4Value{
		Address: k.Address,
		Port:    k.Port,
	}
}

func (k *Service4Key) ToNetwork() ServiceKey {
	n := *k
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

// ToHost converts Service4Key to host byte order.
func (k *Service4Key) ToHost() ServiceKey {
	h := *k
	h.Port = byteorder.NetworkToHost(h.Port).(uint16)
	return &h
}

// Service4Value must match 'struct lb4_service_v2' in "bpf/lib/common.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Service4Value struct {
	BackendID uint32    `align:"backend_id"`
	Count     uint16    `align:"count"`
	RevNat    uint16    `align:"rev_nat_index"`
	Flags     uint8     `align:"flags"`
	Flags2    uint8     `align:"flags2"`
	Pad       pad2uint8 `align:"pad"`
}

func (s *Service4Value) String() string {
	sHost := s.ToHost().(*Service4Value)
	return fmt.Sprintf("%d (%d) [FLAGS: 0x%x]", sHost.BackendID, sHost.RevNat, sHost.Flags)
}

func (s *Service4Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }

func (s *Service4Value) SetCount(count int)   { s.Count = uint16(count) }
func (s *Service4Value) GetCount() int        { return int(s.Count) }
func (s *Service4Value) SetRevNat(id int)     { s.RevNat = uint16(id) }
func (s *Service4Value) GetRevNat() int       { return int(s.RevNat) }
func (s *Service4Value) RevNatKey() RevNatKey { return &RevNat4Key{s.RevNat} }
func (s *Service4Value) SetFlags(flags uint16) {
	s.Flags = uint8(flags & 0xff)
	s.Flags2 = uint8(flags >> 8)
}

func (s *Service4Value) GetFlags() uint16 {
	return (uint16(s.Flags2) << 8) | uint16(s.Flags)
}

func (s *Service4Value) SetSessionAffinityTimeoutSec(t uint32) {
	// Go doesn't support union types, so we use BackendID to access the
	// lb4_service.affinity_timeout field
	s.BackendID = t
}

func (s *Service4Value) SetBackendID(id loadbalancer.BackendID) {
	s.BackendID = uint32(id)
}
func (s *Service4Value) GetBackendID() loadbalancer.BackendID {
	return loadbalancer.BackendID(s.BackendID)
}

func (s *Service4Value) ToNetwork() ServiceValue {
	n := *s
	n.RevNat = byteorder.HostToNetwork(n.RevNat).(uint16)
	return &n
}

// ToHost converts Service4Value to host byte order.
func (s *Service4Value) ToHost() ServiceValue {
	h := *s
	h.RevNat = byteorder.NetworkToHost(h.RevNat).(uint16)
	return &h
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Backend4Key struct {
	ID loadbalancer.BackendID
}

func NewBackend4Key(id loadbalancer.BackendID) *Backend4Key {
	return &Backend4Key{ID: id}
}

func (k *Backend4Key) String() string                  { return fmt.Sprintf("%d", k.ID) }
func (k *Backend4Key) GetKeyPtr() unsafe.Pointer       { return unsafe.Pointer(k) }
func (k *Backend4Key) NewValue() bpf.MapValue          { return &Backend4Value{} }
func (k *Backend4Key) Map() *bpf.Map                   { return Backend4Map }
func (k *Backend4Key) SetID(id loadbalancer.BackendID) { k.ID = id }
func (k *Backend4Key) GetID() loadbalancer.BackendID   { return k.ID }

// Backend4Value must match 'struct lb4_backend' in "bpf/lib/common.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Backend4Value struct {
	Address types.IPv4      `align:"address"`
	Port    uint16          `align:"port"`
	Proto   u8proto.U8proto `align:"proto"`
	Pad     uint8           `align:"pad"`
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
	vHost := v.ToHost().(*Backend4Value)
	return fmt.Sprintf("%s://%s:%d", vHost.Proto, vHost.Address, vHost.Port)
}

func (v *Backend4Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (b *Backend4Value) GetAddress() net.IP { return b.Address.IP() }
func (b *Backend4Value) GetPort() uint16    { return b.Port }
func (b *Backend4Value) GetProtocol() uint8 { return uint8(b.Proto) }

func (v *Backend4Value) ToNetwork() BackendValue {
	n := *v
	n.Port = byteorder.HostToNetwork(n.Port).(uint16)
	return &n
}

// ToHost converts Backend4Value to host byte order.
func (v *Backend4Value) ToHost() BackendValue {
	h := *v
	h.Port = byteorder.NetworkToHost(h.Port).(uint16)
	return &h
}

type Backend4 struct {
	Key   *Backend4Key
	Value *Backend4Value
}

func NewBackend4(id loadbalancer.BackendID, ip net.IP, port uint16, proto u8proto.U8proto) (*Backend4, error) {
	val, err := NewBackend4Value(ip, port, proto)
	if err != nil {
		return nil, err
	}

	return &Backend4{
		Key:   NewBackend4Key(id),
		Value: val,
	}, nil
}

func (b *Backend4) Map() *bpf.Map          { return Backend4Map }
func (b *Backend4) GetKey() BackendKey     { return b.Key }
func (b *Backend4) GetValue() BackendValue { return b.Value }

// SockRevNat4Key is the tuple with address, port and cookie used as key in
// the reverse NAT sock map.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type SockRevNat4Key struct {
	cookie  uint64     `align:"cookie"`
	address types.IPv4 `align:"address"`
	port    int16      `align:"port"`
	pad     int16      `align:"pad"`
}

// SockRevNat4Value is an entry in the reverse NAT sock map.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type SockRevNat4Value struct {
	address     types.IPv4 `align:"address"`
	port        int16      `align:"port"`
	revNatIndex uint16     `align:"rev_nat_index"`
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *SockRevNat4Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *SockRevNat4Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human readable string format.
func (k *SockRevNat4Key) String() string {
	return fmt.Sprintf("[%s]:%d, %d", k.address, k.port, k.cookie)
}

// String converts the value into a human readable string format.
func (v *SockRevNat4Value) String() string {
	return fmt.Sprintf("[%s]:%d, %d", v.address, v.port, v.revNatIndex)
}

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k SockRevNat4Key) NewValue() bpf.MapValue { return &SockRevNat4Value{} }

// CreateSockRevNat4Map creates the reverse NAT sock map.
func CreateSockRevNat4Map() error {
	sockRevNat4Map := bpf.NewMap(SockRevNat4MapName,
		bpf.MapTypeLRUHash,
		&SockRevNat4Key{},
		int(unsafe.Sizeof(SockRevNat4Key{})),
		&SockRevNat4Value{},
		int(unsafe.Sizeof(SockRevNat4Value{})),
		MaxSockRevNat4MapEntries,
		0,
		0,
		bpf.ConvertKeyValue,
	).WithPressureMetric()
	_, err := sockRevNat4Map.Create()
	return err
}

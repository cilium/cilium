// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
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
	// Backend4MapV2Name is the name of the IPv4 LB backends v2 BPF map.
	Backend4MapV2Name = "cilium_lb4_backends_v2"
	// Backend4MapV2Name is the name of the IPv4 LB backends v3 BPF map.
	Backend4MapV3Name = "cilium_lb4_backends_v3"
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
	// Backend4MapV2 is the IPv4 LB backends v2 BPF map.
	Backend4MapV2 *bpf.Map
	// Backend4MapV2 is the IPv4 LB backends v2 BPF map.
	Backend4MapV3 *bpf.Map
	// RevNat4Map is the IPv4 LB reverse NAT BPF map.
	RevNat4Map *bpf.Map
)

// initSVC constructs the IPv4 & IPv6 LB BPF maps used for Services. The maps
// have their maximum entries configured. Note this does not create or open the
// maps; it simply constructs the objects.
func initSVC(params InitParams) {
	ServiceMapMaxEntries = params.ServiceMapMaxEntries
	ServiceBackEndMapMaxEntries = params.BackEndMapMaxEntries
	RevNatMapMaxEntries = params.RevNatMapMaxEntries

	if params.IPv4 {
		Service4MapV2 = bpf.NewMap(Service4MapV2Name,
			bpf.MapTypeHash,
			&Service4Key{},
			int(unsafe.Sizeof(Service4Key{})),
			&Service4Value{},
			int(unsafe.Sizeof(Service4Value{})),
			ServiceMapMaxEntries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(Service4MapV2Name))
		Backend4Map = bpf.NewMap(Backend4MapName,
			bpf.MapTypeHash,
			&Backend4Key{},
			int(unsafe.Sizeof(Backend4Key{})),
			&Backend4Value{},
			int(unsafe.Sizeof(Backend4Value{})),
			ServiceBackEndMapMaxEntries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(Backend4MapName))
		Backend4MapV2 = bpf.NewMap(Backend4MapV2Name,
			bpf.MapTypeHash,
			&Backend4KeyV3{},
			int(unsafe.Sizeof(Backend4KeyV3{})),
			&Backend4Value{},
			int(unsafe.Sizeof(Backend4Value{})),
			ServiceBackEndMapMaxEntries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(Backend4MapV2Name))
		Backend4MapV3 = bpf.NewMap(Backend4MapV3Name,
			bpf.MapTypeHash,
			&Backend4KeyV3{},
			int(unsafe.Sizeof(Backend4KeyV3{})),
			&Backend4ValueV3{},
			int(unsafe.Sizeof(Backend4ValueV3{})),
			ServiceBackEndMapMaxEntries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(Backend4MapV3Name))
		RevNat4Map = bpf.NewMap(RevNat4MapName,
			bpf.MapTypeHash,
			&RevNat4Key{},
			int(unsafe.Sizeof(RevNat4Key{})),
			&RevNat4Value{},
			int(unsafe.Sizeof(RevNat4Value{})),
			RevNatMapMaxEntries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(RevNat4MapName))
	}

	if params.IPv6 {
		Service6MapV2 = bpf.NewMap(Service6MapV2Name,
			bpf.MapTypeHash,
			&Service6Key{},
			int(unsafe.Sizeof(Service6Key{})),
			&Service6Value{},
			int(unsafe.Sizeof(Service6Value{})),
			ServiceMapMaxEntries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(Service6MapV2Name))
		Backend6Map = bpf.NewMap(Backend6MapName,
			bpf.MapTypeHash,
			&Backend6Key{},
			int(unsafe.Sizeof(Backend6Key{})),
			&Backend6Value{},
			int(unsafe.Sizeof(Backend6Value{})),
			ServiceBackEndMapMaxEntries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(Backend6MapName))
		Backend6MapV2 = bpf.NewMap(Backend6MapV2Name,
			bpf.MapTypeHash,
			&Backend6KeyV3{},
			int(unsafe.Sizeof(Backend6KeyV3{})),
			&Backend6Value{},
			int(unsafe.Sizeof(Backend6Value{})),
			ServiceBackEndMapMaxEntries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(Backend6MapV2Name))
		Backend6MapV3 = bpf.NewMap(Backend6MapV3Name,
			bpf.MapTypeHash,
			&Backend6KeyV3{},
			int(unsafe.Sizeof(Backend6KeyV3{})),
			&Backend6ValueV3{},
			int(unsafe.Sizeof(Backend6ValueV3{})),
			ServiceBackEndMapMaxEntries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(Backend6MapV3Name))
		RevNat6Map = bpf.NewMap(RevNat6MapName,
			bpf.MapTypeHash,
			&RevNat6Key{},
			int(unsafe.Sizeof(RevNat6Key{})),
			&RevNat6Value{},
			int(unsafe.Sizeof(RevNat6Value{})),
			RevNatMapMaxEntries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(RevNat6MapName))
	}
}

// The compile-time check for whether the structs implement the interfaces
var _ RevNatKey = (*RevNat4Key)(nil)
var _ RevNatValue = (*RevNat4Value)(nil)
var _ ServiceKey = (*Service4Key)(nil)
var _ ServiceValue = (*Service4Value)(nil)
var _ BackendKey = (*Backend4Key)(nil)
var _ BackendKey = (*Backend4KeyV3)(nil)
var _ BackendValue = (*Backend4Value)(nil)
var _ BackendValue = (*Backend4ValueV3)(nil)
var _ Backend = (*Backend4)(nil)
var _ Backend = (*Backend4V2)(nil)
var _ Backend = (*Backend4V3)(nil)

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
	n.Key = byteorder.HostToNetwork16(n.Key)
	return &n
}

// ToHost converts RevNat4Key to host byte order.
func (k *RevNat4Key) ToHost() RevNatKey {
	h := *k
	h.Key = byteorder.NetworkToHost16(h.Key)
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
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

// ToHost converts RevNat4Value to host byte order.
func (k *RevNat4Value) ToHost() RevNatValue {
	h := *k
	h.Port = byteorder.NetworkToHost16(h.Port)
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

type pad3uint8 [3]uint8

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *pad3uint8) DeepCopyInto(out *pad3uint8) {
	copy(out[:], in[:])
	return
}

// Service4Key must match 'struct lb4_key' in "bpf/lib/common.h".
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
	kHost := k.ToHost().(*Service4Key)
	addr := net.JoinHostPort(kHost.Address.String(), fmt.Sprintf("%d", kHost.Port))
	if kHost.Scope == loadbalancer.ScopeInternal {
		addr += "/i"
	}
	return addr
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
func (k *Service4Key) MapDelete() error          { return k.Map().Delete(k.ToNetwork()) }

func (k *Service4Key) RevNatValue() RevNatValue {
	return &RevNat4Value{
		Address: k.Address,
		Port:    k.Port,
	}
}

func (k *Service4Key) ToNetwork() ServiceKey {
	n := *k
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

// ToHost converts Service4Key to host byte order.
func (k *Service4Key) ToHost() ServiceKey {
	h := *k
	h.Port = byteorder.NetworkToHost16(h.Port)
	return &h
}

// Service4Value must match 'struct lb4_service_v2' in "bpf/lib/common.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Service4Value struct {
	BackendID uint32    `align:"$union0"`
	Count     uint16    `align:"count"`
	RevNat    uint16    `align:"rev_nat_index"`
	Flags     uint8     `align:"flags"`
	Flags2    uint8     `align:"flags2"`
	Pad       pad2uint8 `align:"pad"`
}

func (s *Service4Value) String() string {
	sHost := s.ToHost().(*Service4Value)
	return fmt.Sprintf("%d %d (%d) [0x%x 0x%x]", sHost.BackendID, sHost.Count, sHost.RevNat, sHost.Flags, sHost.Flags2)
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

func (s *Service4Value) SetL7LBProxyPort(port uint16) {
	// Go doesn't support union types, so we use BackendID to access the
	// lb4_service.l7_lb_proxy_port field
	s.BackendID = uint32(byteorder.HostToNetwork16(port))
}

func (s *Service4Value) SetBackendID(id loadbalancer.BackendID) {
	s.BackendID = uint32(id)
}
func (s *Service4Value) GetBackendID() loadbalancer.BackendID {
	return loadbalancer.BackendID(s.BackendID)
}

func (s *Service4Value) ToNetwork() ServiceValue {
	n := *s
	n.RevNat = byteorder.HostToNetwork16(n.RevNat)
	return &n
}

// ToHost converts Service4Value to host byte order.
func (s *Service4Value) ToHost() ServiceValue {
	h := *s
	h.RevNat = byteorder.NetworkToHost16(h.RevNat)
	return &h
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Backend4KeyV3 struct {
	ID loadbalancer.BackendID
}

func NewBackend4KeyV3(id loadbalancer.BackendID) *Backend4KeyV3 {
	return &Backend4KeyV3{ID: id}
}

func (k *Backend4KeyV3) String() string                  { return fmt.Sprintf("%d", k.ID) }
func (k *Backend4KeyV3) GetKeyPtr() unsafe.Pointer       { return unsafe.Pointer(k) }
func (k *Backend4KeyV3) NewValue() bpf.MapValue          { return &Backend4ValueV3{} }
func (k *Backend4KeyV3) Map() *bpf.Map                   { return Backend4MapV3 }
func (k *Backend4KeyV3) SetID(id loadbalancer.BackendID) { k.ID = id }
func (k *Backend4KeyV3) GetID() loadbalancer.BackendID   { return k.ID }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Backend4Key struct {
	ID uint16
}

func (k *Backend4Key) String() string                  { return fmt.Sprintf("%d", k.ID) }
func (k *Backend4Key) GetKeyPtr() unsafe.Pointer       { return unsafe.Pointer(k) }
func (k *Backend4Key) NewValue() bpf.MapValue          { return &Backend4Value{} }
func (k *Backend4Key) Map() *bpf.Map                   { return Backend4Map }
func (k *Backend4Key) SetID(id loadbalancer.BackendID) { k.ID = uint16(id) }
func (k *Backend4Key) GetID() loadbalancer.BackendID   { return loadbalancer.BackendID(k.ID) }

// Backend4Value must match 'struct lb4_backend' in "bpf/lib/common.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Backend4Value struct {
	Address types.IPv4      `align:"address"`
	Port    uint16          `align:"port"`
	Proto   u8proto.U8proto `align:"proto"`
	Flags   uint8           `align:"flags"`
}

func NewBackend4Value(ip net.IP, port uint16, proto u8proto.U8proto, state loadbalancer.BackendState) (*Backend4Value, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("Not an IPv4 address")
	}
	flags := loadbalancer.NewBackendFlags(state)

	val := Backend4Value{
		Port:  port,
		Proto: proto,
		Flags: flags,
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
func (b *Backend4Value) GetIPCluster() cmtypes.AddrCluster {
	return cmtypes.AddrClusterFrom(b.Address.Addr(), 0)
}
func (b *Backend4Value) GetPort() uint16 { return b.Port }
func (b *Backend4Value) GetFlags() uint8 { return b.Flags }

func (v *Backend4Value) ToNetwork() BackendValue {
	n := *v
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

// ToHost converts Backend4Value to host byte order.
func (v *Backend4Value) ToHost() BackendValue {
	h := *v
	h.Port = byteorder.NetworkToHost16(h.Port)
	return &h
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Backend4ValueV3 struct {
	Address   types.IPv4      `align:"address"`
	Port      uint16          `align:"port"`
	Proto     u8proto.U8proto `align:"proto"`
	Flags     uint8           `align:"flags"`
	ClusterID uint8           `align:"cluster_id"`
	Pad       pad3uint8       `align:"pad"`
}

func NewBackend4ValueV3(addrCluster cmtypes.AddrCluster, port uint16, proto u8proto.U8proto, state loadbalancer.BackendState) (*Backend4ValueV3, error) {
	addr := addrCluster.Addr()
	if !addr.Is4() {
		return nil, fmt.Errorf("Not an IPv4 address")
	}

	clusterID := addrCluster.ClusterID()
	if addrCluster.ClusterID() > cmtypes.ClusterIDMax {
		return nil, fmt.Errorf("ClusterID %d is too large. ClusterID > %d is not supported with Backend4ValueV3", clusterID, cmtypes.ClusterIDMax)
	}

	flags := loadbalancer.NewBackendFlags(state)

	val := Backend4ValueV3{
		Port:      port,
		Proto:     proto,
		Flags:     flags,
		ClusterID: uint8(clusterID),
	}

	ip4Array := addr.As4()
	copy(val.Address[:], ip4Array[:])

	return &val, nil
}

func (v *Backend4ValueV3) String() string {
	vHost := v.ToHost().(*Backend4ValueV3)
	return fmt.Sprintf("%s://%s", vHost.Proto, cmtypes.AddrClusterFrom(vHost.Address.Addr(), uint32(vHost.ClusterID)).String())
}

func (v *Backend4ValueV3) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (b *Backend4ValueV3) GetAddress() net.IP { return b.Address.IP() }
func (b *Backend4ValueV3) GetIPCluster() cmtypes.AddrCluster {
	return cmtypes.AddrClusterFrom(b.Address.Addr(), uint32(b.ClusterID))
}
func (b *Backend4ValueV3) GetPort() uint16 { return b.Port }
func (b *Backend4ValueV3) GetFlags() uint8 { return b.Flags }

func (v *Backend4ValueV3) ToNetwork() BackendValue {
	n := *v
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

// ToHost converts Backend4Value to host byte order.
func (v *Backend4ValueV3) ToHost() BackendValue {
	h := *v
	h.Port = byteorder.NetworkToHost16(h.Port)
	return &h
}

type Backend4V3 struct {
	Key   *Backend4KeyV3
	Value *Backend4ValueV3
}

func NewBackend4V3(id loadbalancer.BackendID, addrCluster cmtypes.AddrCluster, port uint16,
	proto u8proto.U8proto, state loadbalancer.BackendState) (*Backend4V3, error) {
	val, err := NewBackend4ValueV3(addrCluster, port, proto, state)
	if err != nil {
		return nil, err
	}

	return &Backend4V3{
		Key:   NewBackend4KeyV3(id),
		Value: val,
	}, nil
}

func (b *Backend4V3) Map() *bpf.Map          { return Backend4MapV3 }
func (b *Backend4V3) GetKey() BackendKey     { return b.Key }
func (b *Backend4V3) GetValue() BackendValue { return b.Value }

type Backend4V2 struct {
	Key   *Backend4KeyV3
	Value *Backend4Value
}

func NewBackend4V2(id loadbalancer.BackendID, ip net.IP, port uint16, proto u8proto.U8proto,
	state loadbalancer.BackendState) (*Backend4V2, error) {
	val, err := NewBackend4Value(ip, port, proto, state)
	if err != nil {
		return nil, err
	}

	return &Backend4V2{
		Key:   NewBackend4KeyV3(id),
		Value: val,
	}, nil
}

func (b *Backend4V2) Map() *bpf.Map          { return Backend4MapV2 }
func (b *Backend4V2) GetKey() BackendKey     { return b.Key }
func (b *Backend4V2) GetValue() BackendValue { return b.Value }

type Backend4 struct {
	Key   *Backend4Key
	Value *Backend4Value
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
		bpf.ConvertKeyValue,
	).WithPressureMetric()
	return sockRevNat4Map.Create()
}

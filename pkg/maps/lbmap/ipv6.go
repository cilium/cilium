// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
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
	// Backend6MapV2Name is the name of the IPv6 LB backends v2 BPF map.
	Backend6MapV2Name = "cilium_lb6_backends_v2"
	// Backend6MapV3Name is the name of the IPv6 LB backends v3 BPF map.
	Backend6MapV3Name = "cilium_lb6_backends_v3"
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
	// Backend6MapV2 is the IPv6 LB backends v2 BPF map.
	Backend6MapV2 *bpf.Map
	// Backend6MapV3 is the IPv6 LB backends v3 BPF map.
	Backend6MapV3 *bpf.Map
	// RevNat6Map is the IPv6 LB reverse NAT BPF map.
	RevNat6Map *bpf.Map
	// SockRevNat6Map is the IPv6 LB sock reverse NAT BPF map.
	SockRevNat6Map *bpf.Map
)

// The compile-time check for whether the structs implement the interfaces
var _ RevNatKey = (*RevNat6Key)(nil)
var _ RevNatValue = (*RevNat6Value)(nil)
var _ ServiceKey = (*Service6Key)(nil)
var _ ServiceValue = (*Service6Value)(nil)
var _ BackendKey = (*Backend6Key)(nil)
var _ BackendValue = (*Backend6Value)(nil)
var _ Backend = (*Backend6)(nil)

type RevNat6Key struct {
	Key uint16
}

func NewRevNat6Key(value uint16) *RevNat6Key {
	return &RevNat6Key{value}
}

func (v *RevNat6Key) Map() *bpf.Map   { return RevNat6Map }
func (v *RevNat6Key) String() string  { return fmt.Sprintf("%d", v.ToHost().(*RevNat6Key).Key) }
func (v *RevNat6Key) New() bpf.MapKey { return &RevNat6Key{} }
func (v *RevNat6Key) GetKey() uint16  { return v.Key }

// ToNetwork converts RevNat6Key to network byte order.
func (v *RevNat6Key) ToNetwork() RevNatKey {
	n := *v
	n.Key = byteorder.HostToNetwork16(n.Key)
	return &n
}

// ToNetwork converts RevNat6Key to host byte order.
func (v *RevNat6Key) ToHost() RevNatKey {
	h := *v
	h.Key = byteorder.NetworkToHost16(h.Key)
	return &h
}

type RevNat6Value struct {
	Address types.IPv6 `align:"address"`
	Port    uint16     `align:"port"`
}

func (v *RevNat6Value) String() string {
	vHost := v.ToHost().(*RevNat6Value)
	return net.JoinHostPort(vHost.Address.String(), fmt.Sprintf("%d", vHost.Port))
}

func (v *RevNat6Value) New() bpf.MapValue { return &RevNat6Value{} }

// ToNetwork converts RevNat6Value to network byte order.
func (v *RevNat6Value) ToNetwork() RevNatValue {
	n := *v
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

// ToNetwork converts RevNat6Value to Host byte order.
func (v *RevNat6Value) ToHost() RevNatValue {
	h := *v
	h.Port = byteorder.NetworkToHost16(h.Port)
	return &h
}

// Service6Key must match 'struct lb6_key' in "bpf/lib/common.h".
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
	kHost := k.ToHost().(*Service6Key)
	if kHost.Scope == loadbalancer.ScopeInternal {
		return fmt.Sprintf("[%s]:%d/%s/i (%d)", kHost.Address, kHost.Port, u8proto.U8proto(kHost.Proto).String(), kHost.BackendSlot)
	} else {
		return fmt.Sprintf("[%s]:%d/%s (%d)", kHost.Address, kHost.Port, u8proto.U8proto(kHost.Proto).String(), kHost.BackendSlot)
	}
}

func (k *Service6Key) New() bpf.MapKey { return &Service6Key{} }

func (k *Service6Key) IsIPv6() bool            { return true }
func (k *Service6Key) IsSurrogate() bool       { return k.GetAddress().IsUnspecified() }
func (k *Service6Key) Map() *bpf.Map           { return Service6MapV2 }
func (k *Service6Key) SetBackendSlot(slot int) { k.BackendSlot = uint16(slot) }
func (k *Service6Key) GetBackendSlot() int     { return int(k.BackendSlot) }
func (k *Service6Key) SetScope(scope uint8)    { k.Scope = scope }
func (k *Service6Key) GetScope() uint8         { return k.Scope }
func (k *Service6Key) GetAddress() net.IP      { return k.Address.IP() }
func (k *Service6Key) GetPort() uint16         { return k.Port }
func (k *Service6Key) GetProtocol() uint8      { return k.Proto }
func (k *Service6Key) MapDelete() error        { return k.Map().Delete(k.ToNetwork()) }

func (k *Service6Key) RevNatValue() RevNatValue {
	return &RevNat6Value{
		Address: k.Address,
		Port:    k.Port,
	}
}

func (k *Service6Key) ToNetwork() ServiceKey {
	n := *k
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

// ToHost converts Service6Key to host byte order.
func (k *Service6Key) ToHost() ServiceKey {
	h := *k
	h.Port = byteorder.NetworkToHost16(h.Port)
	return &h
}

// Service6Value must match 'struct lb6_service' in "bpf/lib/common.h".
type Service6Value struct {
	BackendID uint32 `align:"$union0"`
	Count     uint16 `align:"count"`
	RevNat    uint16 `align:"rev_nat_index"`
	Flags     uint8  `align:"flags"`
	Flags2    uint8  `align:"flags2"`
	QCount    uint16 `align:"qcount"`
}

func (s *Service6Value) New() bpf.MapValue { return &Service6Value{} }

func (s *Service6Value) String() string {
	sHost := s.ToHost().(*Service6Value)
	return fmt.Sprintf("%d %d[%d] (%d) [0x%x 0x%x]", sHost.BackendID, sHost.Count, sHost.QCount, sHost.RevNat, sHost.Flags, sHost.Flags2)
}

func (s *Service6Value) SetCount(count int)   { s.Count = uint16(count) }
func (s *Service6Value) GetCount() int        { return int(s.Count) }
func (s *Service6Value) SetQCount(count int)  { s.QCount = uint16(count) }
func (s *Service6Value) GetQCount() int       { return int(s.QCount) }
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

func (s *Service6Value) SetL7LBProxyPort(port uint16) {
	// Go doesn't support union types, so we use BackendID to access the
	// lb6_service.l7_lb_proxy_port field
	s.BackendID = uint32(byteorder.HostToNetwork16(port))
}

func (s *Service6Value) SetBackendID(id loadbalancer.BackendID) {
	s.BackendID = uint32(id)
}
func (s *Service6Value) GetBackendID() loadbalancer.BackendID {
	return loadbalancer.BackendID(s.BackendID)
}

func (s *Service6Value) ToNetwork() ServiceValue {
	n := *s
	n.RevNat = byteorder.HostToNetwork16(n.RevNat)
	return &n
}

// ToHost converts Service6Value to host byte order.
func (s *Service6Value) ToHost() ServiceValue {
	h := *s
	h.RevNat = byteorder.NetworkToHost16(h.RevNat)
	return &h
}

type Backend6KeyV3 struct {
	ID loadbalancer.BackendID
}

func NewBackend6KeyV3(id loadbalancer.BackendID) *Backend6KeyV3 {
	return &Backend6KeyV3{ID: id}
}

func (k *Backend6KeyV3) String() string                  { return fmt.Sprintf("%d", k.ID) }
func (k *Backend6KeyV3) New() bpf.MapKey                 { return &Backend6KeyV3{} }
func (k *Backend6KeyV3) Map() *bpf.Map                   { return Backend6MapV3 }
func (k *Backend6KeyV3) SetID(id loadbalancer.BackendID) { k.ID = id }
func (k *Backend6KeyV3) GetID() loadbalancer.BackendID   { return k.ID }

type Backend6Key struct {
	ID uint16
}

func (k *Backend6Key) String() string                  { return fmt.Sprintf("%d", k.ID) }
func (k *Backend6Key) New() bpf.MapKey                 { return &Backend6Key{} }
func (k *Backend6Key) Map() *bpf.Map                   { return Backend6Map }
func (k *Backend6Key) SetID(id loadbalancer.BackendID) { k.ID = uint16(id) }
func (k *Backend6Key) GetID() loadbalancer.BackendID   { return loadbalancer.BackendID(k.ID) }

// Backend6Value must match 'struct lb6_backend' in "bpf/lib/common.h".
type Backend6Value struct {
	Address types.IPv6      `align:"address"`
	Port    uint16          `align:"port"`
	Proto   u8proto.U8proto `align:"proto"`
	Flags   uint8           `align:"flags"`
}

func NewBackend6Value(ip net.IP, port uint16, proto u8proto.U8proto, state loadbalancer.BackendState) (*Backend6Value, error) {
	ip6 := ip.To16()
	if ip6 == nil {
		return nil, fmt.Errorf("Not an IPv6 address")
	}
	flags := loadbalancer.NewBackendFlags(state)

	val := Backend6Value{
		Port:  port,
		Proto: proto,
		Flags: flags,
	}
	copy(val.Address[:], ip.To16())

	return &val, nil
}

func (v *Backend6Value) String() string {
	vHost := v.ToHost().(*Backend6Value)
	return fmt.Sprintf("%s://[%s]:%d", vHost.Proto, vHost.Address, vHost.Port)
}
func (v *Backend6Value) New() bpf.MapValue { return &Backend6Value{} }

func (b *Backend6Value) GetAddress() net.IP { return b.Address.IP() }
func (b *Backend6Value) GetIPCluster() cmtypes.AddrCluster {
	return cmtypes.AddrClusterFrom(b.Address.Addr(), 0)
}
func (b *Backend6Value) GetPort() uint16    { return b.Port }
func (b *Backend6Value) GetProtocol() uint8 { return uint8(b.Proto) }
func (b *Backend6Value) GetFlags() uint8    { return b.Flags }
func (b *Backend6Value) GetZone() uint8     { return 0 }

func (v *Backend6Value) ToNetwork() BackendValue {
	n := *v
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

// ToHost converts Backend6Value to host byte order.
func (v *Backend6Value) ToHost() BackendValue {
	h := *v
	h.Port = byteorder.NetworkToHost16(h.Port)
	return &h
}

type Backend6ValueV3 struct {
	Address   types.IPv6      `align:"address"`
	Port      uint16          `align:"port"`
	Proto     u8proto.U8proto `align:"proto"`
	Flags     uint8           `align:"flags"`
	ClusterID uint16          `align:"cluster_id"`
	Zone      uint8           `align:"zone"`
	Pad       uint8           `align:"pad"`
}

func NewBackend6ValueV3(addrCluster cmtypes.AddrCluster, port uint16, proto u8proto.U8proto, state loadbalancer.BackendState, zone uint8) (*Backend6ValueV3, error) {
	addr := addrCluster.Addr()

	// It is possible to have IPv4 backend in IPv6. We have NAT46/64.
	if !addr.Is4() && !addr.Is6() {
		return nil, fmt.Errorf("Not a valid IP address")
	}

	if addrCluster.ClusterID() > cmtypes.ClusterIDMax {
		return nil, fmt.Errorf("ClusterID %d is too large. ClusterID > %d is not supported with Backend6ValueV3", addrCluster.ClusterID(), cmtypes.ClusterIDMax)
	}

	flags := loadbalancer.NewBackendFlags(state)

	val := Backend6ValueV3{
		Port:  port,
		Proto: proto,
		Flags: flags,
		Zone:  zone,
	}

	ipv6Array := addr.As16()
	copy(val.Address[:], ipv6Array[:])

	return &val, nil
}

func (v *Backend6ValueV3) String() string {
	vHost := v.ToHost().(*Backend6ValueV3)
	if v.Zone != 0 {
		return fmt.Sprintf("%s://%s[%s]", vHost.Proto, cmtypes.AddrClusterFrom(vHost.Address.Addr(), uint32(vHost.ClusterID)), option.Config.GetZone(v.Zone))
	}
	return fmt.Sprintf("%s://%s", vHost.Proto, cmtypes.AddrClusterFrom(vHost.Address.Addr(), uint32(vHost.ClusterID)))
}

func (v *Backend6ValueV3) New() bpf.MapValue { return &Backend6ValueV3{} }

func (b *Backend6ValueV3) GetAddress() net.IP { return b.Address.IP() }
func (b *Backend6ValueV3) GetIPCluster() cmtypes.AddrCluster {
	return cmtypes.AddrClusterFrom(b.Address.Addr(), uint32(b.ClusterID))
}
func (b *Backend6ValueV3) GetPort() uint16    { return b.Port }
func (b *Backend6ValueV3) GetProtocol() uint8 { return uint8(b.Proto) }
func (b *Backend6ValueV3) GetFlags() uint8    { return b.Flags }
func (b *Backend6ValueV3) GetZone() uint8     { return b.Zone }

func (v *Backend6ValueV3) ToNetwork() BackendValue {
	n := *v
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

// ToHost converts Backend6ValueV3 to host byte order.
func (v *Backend6ValueV3) ToHost() BackendValue {
	h := *v
	h.Port = byteorder.NetworkToHost16(h.Port)
	return &h
}

type Backend6V3 struct {
	Key   *Backend6KeyV3
	Value *Backend6ValueV3
}

func NewBackend6V3(id loadbalancer.BackendID, addrCluster cmtypes.AddrCluster, port uint16,
	proto u8proto.U8proto, state loadbalancer.BackendState, zone uint8) (*Backend6V3, error) {
	val, err := NewBackend6ValueV3(addrCluster, port, proto, state, zone)
	if err != nil {
		return nil, err
	}

	return &Backend6V3{
		Key:   NewBackend6KeyV3(id),
		Value: val,
	}, nil
}

func (b *Backend6V3) Map() *bpf.Map          { return Backend6MapV3 }
func (b *Backend6V3) GetKey() BackendKey     { return b.Key }
func (b *Backend6V3) GetValue() BackendValue { return b.Value }

type Backend6V2 struct {
	Key   *Backend6KeyV3
	Value *Backend6Value
}

func NewBackend6V2(id loadbalancer.BackendID, ip net.IP, port uint16, proto u8proto.U8proto,
	state loadbalancer.BackendState) (*Backend6V2, error) {
	val, err := NewBackend6Value(ip, port, proto, state)
	if err != nil {
		return nil, err
	}

	return &Backend6V2{
		Key:   NewBackend6KeyV3(id),
		Value: val,
	}, nil
}

func (b *Backend6V2) Map() *bpf.Map          { return Backend6MapV2 }
func (b *Backend6V2) GetKey() BackendKey     { return b.Key }
func (b *Backend6V2) GetValue() BackendValue { return b.Value }

type Backend6 struct {
	Key   *Backend6Key
	Value *Backend6Value
}

func (b *Backend6) Map() *bpf.Map          { return Backend6Map }
func (b *Backend6) GetKey() BackendKey     { return b.Key }
func (b *Backend6) GetValue() BackendValue { return b.Value }

// SockRevNat6Key is the tuple with address, port and cookie used as key in
// the reverse NAT sock map.
type SockRevNat6Key struct {
	Cookie  uint64     `align:"cookie"`
	Address types.IPv6 `align:"address"`
	Port    int16      `align:"port"`
	_       [6]byte
}

// SizeofSockRevNat6Key is the size of type SockRevNat6Key.
const SizeofSockRevNat6Key = int(unsafe.Sizeof(SockRevNat6Key{}))

// SockRevNat6Value is an entry in the reverse NAT sock map.
type SockRevNat6Value struct {
	address     types.IPv6 `align:"address"`
	port        int16      `align:"port"`
	revNatIndex uint16     `align:"rev_nat_index"`
}

// SizeofSockRevNat6Value is the size of type SockRevNat6Value.
const SizeofSockRevNat6Value = int(unsafe.Sizeof(SockRevNat6Value{}))

func (k *SockRevNat6Key) Map() *bpf.Map { return SockRevNat6Map }

func NewSockRevNat6Key(cookie uint64, addr net.IP, port uint16) *SockRevNat6Key {
	var key SockRevNat6Key

	key.Cookie = cookie
	key.Port = int16(byteorder.NetworkToHost16(port))
	ipv6Array := addr.To16()
	copy(key.Address[:], ipv6Array[:])

	return &key
}

// String converts the key into a human readable string format.
func (k *SockRevNat6Key) String() string {
	return fmt.Sprintf("[%s]:%d, %d", k.Address, k.Port, k.Cookie)
}

func (k *SockRevNat6Key) New() bpf.MapKey { return &SockRevNat6Key{} }

// String converts the value into a human readable string format.
func (v *SockRevNat6Value) String() string {
	return fmt.Sprintf("[%s]:%d, %d", v.address, v.port, v.revNatIndex)
}

func (v *SockRevNat6Value) New() bpf.MapValue { return &SockRevNat6Value{} }

// CreateSockRevNat6Map creates the reverse NAT sock map.
func CreateSockRevNat6Map() error {
	SockRevNat6Map = bpf.NewMap(SockRevNat6MapName,
		ebpf.LRUHash,
		&SockRevNat6Key{},
		&SockRevNat6Value{},
		MaxSockRevNat6MapEntries,
		0,
	).WithPressureMetric()
	return SockRevNat6Map.OpenOrCreate()
}

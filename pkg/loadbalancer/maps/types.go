// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"fmt"
	"net"
	"strconv"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

//
// Service (i.e. service frontend)
//

const (
	// Service4MapV2Name is the name of the IPv4 LB Services v2 BPF map.
	Service4MapV2Name = "cilium_lb4_services_v2"

	// Service6MapV2Name is the name of the IPv6 LB Services v2 BPF map.
	Service6MapV2Name = "cilium_lb6_services_v2"
)

// ServiceKey is the interface describing key for services map v2.
type ServiceKey interface {
	bpf.MapKey

	// Return true if the key is of type IPv6
	IsIPv6() bool

	// IsSurrogate returns true on zero-address
	IsSurrogate() bool

	// Set backend slot for the key
	SetBackendSlot(slot int)

	// Get backend slot of the key
	GetBackendSlot() int

	// Set lookup scope for the key
	SetScope(scope uint8)

	// Get lookup scope for the key
	GetScope() uint8

	// Get frontend IP address
	GetAddress() net.IP

	// Get frontend port
	GetPort() uint16

	// Get protocol
	GetProtocol() uint8

	// Returns a RevNatValue matching a ServiceKey
	RevNatValue() RevNatValue

	// ToNetwork converts fields to network byte order.
	ToNetwork() ServiceKey

	// ToHost converts fields to host byte order.
	ToHost() ServiceKey
}

// ServiceValue is the interface describing protocol independent value for services map v2.
type ServiceValue interface {
	bpf.MapValue

	// Set the number of backends
	SetCount(int)

	// Get the number of backends
	GetCount() int

	// Set the number of quarantined backends
	SetQCount(int)

	// Get the number of quarantined backends
	GetQCount() int

	// Set reverse NAT identifier
	SetRevNat(int)

	// Get reverse NAT identifier
	GetRevNat() int

	// Set flags
	SetFlags(uint16)

	// Get flags
	GetFlags() uint16

	// Set timeout for sessionAffinity=clientIP
	SetSessionAffinityTimeoutSec(t uint32) error

	// Get timeout for sessionAffinity=clientIP
	GetSessionAffinityTimeoutSec() uint32

	// Set proxy port for l7 loadbalancer services
	SetL7LBProxyPort(port uint16)

	// Get proxy port for l7 loadbalancer services
	GetL7LBProxyPort() uint16

	// Set backend identifier
	SetBackendID(id loadbalancer.BackendID)

	// Get backend identifier
	GetBackendID() loadbalancer.BackendID

	// Returns a RevNatKey matching a ServiceValue
	RevNatKey() RevNatKey

	// Convert fields to network byte order.
	ToNetwork() ServiceValue

	// ToHost converts fields to host byte order.
	ToHost() ServiceValue

	// Set LoadBalancing Algorithm for Service
	SetLbAlg(loadbalancer.SVCLoadBalancingAlgorithm)

	// Get LoadBalancing Algorithm for Service
	GetLbAlg() loadbalancer.SVCLoadBalancingAlgorithm
}

type pad2uint8 [2]uint8

// Service4Key must match 'struct lb4_key' in "bpf/lib/common.h".
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
	addr += fmt.Sprintf("/%s", u8proto.U8proto(kHost.Proto).String())
	if kHost.Scope == loadbalancer.ScopeInternal {
		addr += "/i"
	}
	addr = fmt.Sprintf("%s (%d)", addr, kHost.BackendSlot)
	return addr
}

func (k *Service4Key) New() bpf.MapKey { return &Service4Key{} }

func (k *Service4Key) IsIPv6() bool            { return false }
func (k *Service4Key) IsSurrogate() bool       { return k.GetAddress().IsUnspecified() }
func (k *Service4Key) SetBackendSlot(slot int) { k.BackendSlot = uint16(slot) }
func (k *Service4Key) GetBackendSlot() int     { return int(k.BackendSlot) }
func (k *Service4Key) SetScope(scope uint8)    { k.Scope = scope }
func (k *Service4Key) GetScope() uint8         { return k.Scope }
func (k *Service4Key) GetAddress() net.IP      { return k.Address.IP() }
func (k *Service4Key) GetPort() uint16         { return k.Port }
func (k *Service4Key) GetProtocol() uint8      { return k.Proto }

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

// Service4Value must match 'struct lb4_service' in "bpf/lib/common.h".
type Service4Value struct {
	BackendID uint32 `align:"$union0"`
	Count     uint16 `align:"count"`
	RevNat    uint16 `align:"rev_nat_index"`
	Flags     uint8  `align:"flags"`
	Flags2    uint8  `align:"flags2"`
	QCount    uint16 `align:"qcount"`
}

func (s *Service4Value) New() bpf.MapValue { return &Service4Value{} }

func (s *Service4Value) String() string {
	sHost := s.ToHost().(*Service4Value)
	return fmt.Sprintf("%d %d[%d] (%d) [0x%x 0x%x]", sHost.BackendID, sHost.Count, sHost.QCount, sHost.RevNat, sHost.Flags, sHost.Flags2)
}

func (s *Service4Value) SetCount(count int)   { s.Count = uint16(count) }
func (s *Service4Value) GetCount() int        { return int(s.Count) }
func (s *Service4Value) SetQCount(count int)  { s.QCount = uint16(count) }
func (s *Service4Value) GetQCount() int       { return int(s.QCount) }
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

const (
	sessionAffinityMask uint32 = 0x00ff_ffff
	lbAlgMask           uint32 = 0xff00_0000
)

func (s *Service4Value) SetSessionAffinityTimeoutSec(t uint32) error {
	// Go doesn't support union types, so we use BackendID to access the
	// lb4_service.affinity_timeout field. Also, for the master entry the
	// LB algorithm can be set independently, so we need to preseve the
	// first 8 bits and only assign to the latter 24 bits.
	if t > sessionAffinityMask {
		return fmt.Errorf("session affinity timeout %d does not fit into 24 bits (is larger than 16777215)", t)
	}
	s.BackendID = (s.BackendID & lbAlgMask) + (t & sessionAffinityMask)
	return nil
}

func (s *Service4Value) GetSessionAffinityTimeoutSec() uint32 {
	return s.BackendID & sessionAffinityMask
}

func (s *Service4Value) SetL7LBProxyPort(port uint16) {
	// Go doesn't support union types, so we use BackendID to access the
	// lb4_service.l7_lb_proxy_port field
	s.BackendID = uint32(byteorder.HostToNetwork16(port))
}

func (s *Service4Value) GetL7LBProxyPort() uint16 {
	return byteorder.HostToNetwork16(uint16(s.BackendID))
}

func (s *Service4Value) SetBackendID(id loadbalancer.BackendID) {
	s.BackendID = uint32(id)
}
func (s *Service4Value) GetBackendID() loadbalancer.BackendID {
	return loadbalancer.BackendID(s.BackendID)
}

func (s *Service4Value) GetLbAlg() loadbalancer.SVCLoadBalancingAlgorithm {
	return loadbalancer.SVCLoadBalancingAlgorithm(uint8(uint32(s.BackendID) >> 24))
}

func (s *Service4Value) SetLbAlg(lb loadbalancer.SVCLoadBalancingAlgorithm) {
	// SessionAffinityTimeoutSec can be set independently on the latter 24 bits,
	// so we only modify the first 8 bits.
	s.BackendID = uint32(lb)<<24 + (s.BackendID & sessionAffinityMask)
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
func (k *Service6Key) SetBackendSlot(slot int) { k.BackendSlot = uint16(slot) }
func (k *Service6Key) GetBackendSlot() int     { return int(k.BackendSlot) }
func (k *Service6Key) SetScope(scope uint8)    { k.Scope = scope }
func (k *Service6Key) GetScope() uint8         { return k.Scope }
func (k *Service6Key) GetAddress() net.IP      { return k.Address.IP() }
func (k *Service6Key) GetPort() uint16         { return k.Port }
func (k *Service6Key) GetProtocol() uint8      { return k.Proto }

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

func (s *Service6Value) GetLbAlg() loadbalancer.SVCLoadBalancingAlgorithm {
	return loadbalancer.SVCLoadBalancingAlgorithm(uint8(uint32(s.BackendID) >> 24))
}

func (s *Service6Value) SetLbAlg(lb loadbalancer.SVCLoadBalancingAlgorithm) {
	// See (* Service6Value).SetLbAlg() for comment
	s.BackendID = uint32(lb)<<24 + (s.BackendID & sessionAffinityMask)
}

func (s *Service6Value) GetFlags() uint16 {
	return (uint16(s.Flags2) << 8) | uint16(s.Flags)
}

func (s *Service6Value) SetSessionAffinityTimeoutSec(t uint32) error {
	// See (* Service4Value).SetSessionAffinityTimeoutSec() for comment
	if t > sessionAffinityMask {
		return fmt.Errorf("session affinity timeout %d does not fit into 24 bits (is larger than 16777215)", t)
	}
	s.BackendID = (s.BackendID & lbAlgMask) + (t & sessionAffinityMask)
	return nil
}

func (s *Service6Value) GetSessionAffinityTimeoutSec() uint32 {
	return s.BackendID & sessionAffinityMask
}

func (s *Service6Value) SetL7LBProxyPort(port uint16) {
	// Go doesn't support union types, so we use BackendID to access the
	// lb6_service.l7_lb_proxy_port field
	s.BackendID = uint32(byteorder.HostToNetwork16(port))
}

func (s *Service6Value) GetL7LBProxyPort() uint16 {
	return byteorder.HostToNetwork16(uint16(s.BackendID))
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

var _ ServiceKey = (*Service4Key)(nil)
var _ ServiceValue = (*Service4Value)(nil)
var _ ServiceKey = (*Service6Key)(nil)
var _ ServiceValue = (*Service6Value)(nil)

//
// Backend
//

const (
	// Backend4MapName is the name of the IPv4 LB backends BPF map.
	Backend4MapName = "cilium_lb4_backends"
	// Backend4MapV2Name is the name of the IPv4 LB backends v2 BPF map.
	Backend4MapV2Name = "cilium_lb4_backends_v2"
	// Backend4MapV3Name is the name of the IPv4 LB backends v3 BPF map.
	Backend4MapV3Name = "cilium_lb4_backends_v3"
	// RevNat4MapName is the name of the IPv4 LB reverse NAT BPF map.

	// Backend6MapName is the name of the IPv6 LB backends BPF map.
	Backend6MapName = "cilium_lb6_backends"
	// Backend6MapV2Name is the name of the IPv6 LB backends v2 BPF map.
	Backend6MapV2Name = "cilium_lb6_backends_v2"
	// Backend6MapV3Name is the name of the IPv6 LB backends v3 BPF map.
	Backend6MapV3Name = "cilium_lb6_backends_v3"
)

// BackendKey is the interface describing protocol independent backend key.
type BackendKey interface {
	bpf.MapKey

	// Set backend identifier
	SetID(loadbalancer.BackendID)

	// Get backend identifier
	GetID() loadbalancer.BackendID
}

// BackendValue is the interface describing backend value.
type BackendValue interface {
	bpf.MapValue

	// Get backend address
	GetAddress() cmtypes.AddrCluster

	// Get backend port
	GetPort() uint16

	// Get backend protocol
	GetProtocol() uint8

	// Get backend flags
	GetFlags() uint8

	// Get zone
	GetZone() uint8

	// Convert fields to network byte order.
	ToNetwork() BackendValue

	// ToHost converts fields to host byte order.
	ToHost() BackendValue
}

// Backend is the interface describing protocol independent backend used by services v2.
type Backend interface {
	// Get key of the backend entry
	GetKey() BackendKey

	// Get value of the backend entry
	GetValue() BackendValue
}

type Backend4KeyV3 struct {
	ID loadbalancer.BackendID
}

func NewBackend4KeyV3(id loadbalancer.BackendID) *Backend4KeyV3 {
	return &Backend4KeyV3{ID: id}
}

func (k *Backend4KeyV3) String() string                  { return fmt.Sprintf("%d", k.ID) }
func (k *Backend4KeyV3) New() bpf.MapKey                 { return &Backend4KeyV3{} }
func (k *Backend4KeyV3) SetID(id loadbalancer.BackendID) { k.ID = id }
func (k *Backend4KeyV3) GetID() loadbalancer.BackendID   { return k.ID }

type Backend4ValueV3 struct {
	Address   types.IPv4      `align:"address"`
	Port      uint16          `align:"port"`
	Proto     u8proto.U8proto `align:"proto"`
	Flags     uint8           `align:"flags"`
	ClusterID uint16          `align:"cluster_id"`
	Zone      uint8           `align:"zone"`
	Pad       uint8           `align:"pad"`
}

func NewBackend4ValueV3(addrCluster cmtypes.AddrCluster, port uint16, proto u8proto.U8proto, state loadbalancer.BackendState, zone uint8) (*Backend4ValueV3, error) {
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
		ClusterID: uint16(clusterID),
		Zone:      zone,
	}

	ip4Array := addr.As4()
	copy(val.Address[:], ip4Array[:])

	return &val, nil
}

func (v *Backend4ValueV3) String() string {
	vHost := v.ToHost().(*Backend4ValueV3)
	if v.Zone != 0 {
		return fmt.Sprintf("%s://%s[%s]", vHost.Proto, cmtypes.AddrClusterFrom(vHost.Address.Addr(), uint32(vHost.ClusterID)).String(), option.Config.GetZone(v.Zone))
	}
	return fmt.Sprintf("%s://%s", vHost.Proto, cmtypes.AddrClusterFrom(vHost.Address.Addr(), uint32(vHost.ClusterID)).String())
}

func (b *Backend4ValueV3) New() bpf.MapValue { return &Backend4ValueV3{} }

func (b *Backend4ValueV3) GetAddress() cmtypes.AddrCluster {
	return cmtypes.AddrClusterFrom(b.Address.Addr(), uint32(b.ClusterID))
}
func (b *Backend4ValueV3) GetPort() uint16    { return b.Port }
func (b *Backend4ValueV3) GetProtocol() uint8 { return uint8(b.Proto) }
func (b *Backend4ValueV3) GetFlags() uint8    { return b.Flags }
func (b *Backend4ValueV3) GetZone() uint8     { return b.Zone }

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
	proto u8proto.U8proto, state loadbalancer.BackendState, zone uint8) (*Backend4V3, error) {
	val, err := NewBackend4ValueV3(addrCluster, port, proto, state, zone)
	if err != nil {
		return nil, err
	}

	return &Backend4V3{
		Key:   NewBackend4KeyV3(id),
		Value: val,
	}, nil
}

func (b *Backend4V3) GetKey() BackendKey     { return b.Key }
func (b *Backend4V3) GetValue() BackendValue { return b.Value }

type Backend6KeyV3 struct {
	ID loadbalancer.BackendID
}

func NewBackend6KeyV3(id loadbalancer.BackendID) *Backend6KeyV3 {
	return &Backend6KeyV3{ID: id}
}

func (k *Backend6KeyV3) String() string                  { return fmt.Sprintf("%d", k.ID) }
func (k *Backend6KeyV3) New() bpf.MapKey                 { return &Backend6KeyV3{} }
func (k *Backend6KeyV3) SetID(id loadbalancer.BackendID) { k.ID = id }
func (k *Backend6KeyV3) GetID() loadbalancer.BackendID   { return k.ID }

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

func (b *Backend6ValueV3) GetAddress() cmtypes.AddrCluster {
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

func (b *Backend6V3) GetKey() BackendKey     { return b.Key }
func (b *Backend6V3) GetValue() BackendValue { return b.Value }

var _ BackendKey = (*Backend4KeyV3)(nil)
var _ BackendValue = (*Backend4ValueV3)(nil)
var _ Backend = (*Backend4V3)(nil)

//
// RevNat (reverse nat)
//

const (
	// RevNat4MapName is the name of the IPv4 LB reverse NAT BPF map.
	RevNat4MapName = "cilium_lb4_reverse_nat"

	// RevNat6MapName is the name of the IPv6 LB reverse NAT BPF map.
	RevNat6MapName = "cilium_lb6_reverse_nat"
)

type RevNatKey interface {
	bpf.MapKey

	// ToNetwork converts fields to network byte order.
	ToNetwork() RevNatKey

	// Returns the key value
	GetKey() loadbalancer.ServiceID

	// ToHost converts fields to host byte order.
	ToHost() RevNatKey
}

type RevNatValue interface {
	bpf.MapValue

	// ToNetwork converts fields to network byte order.
	ToNetwork() RevNatValue

	// ToHost converts fields to host byte order.
	ToHost() RevNatValue
}

type RevNat4Key struct {
	Key uint16
}

func NewRevNat4Key(id loadbalancer.ServiceID) *RevNat4Key {
	return &RevNat4Key{uint16(id)}
}

func (k *RevNat4Key) String() string                 { return fmt.Sprintf("%d", k.ToHost().(*RevNat4Key).Key) }
func (k *RevNat4Key) New() bpf.MapKey                { return &RevNat4Key{} }
func (v *RevNat4Key) GetKey() loadbalancer.ServiceID { return loadbalancer.ServiceID(v.Key) }

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

type RevNat4Value struct {
	Address types.IPv4 `align:"address"`
	Port    uint16     `align:"port"`
}

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

func (v *RevNat4Value) New() bpf.MapValue { return &RevNat4Value{} }

type RevNat6Key struct {
	Key uint16
}

func NewRevNat6Key(value uint16) *RevNat6Key {
	return &RevNat6Key{value}
}

func (v *RevNat6Key) String() string                 { return fmt.Sprintf("%d", v.ToHost().(*RevNat6Key).Key) }
func (v *RevNat6Key) New() bpf.MapKey                { return &RevNat6Key{} }
func (v *RevNat6Key) GetKey() loadbalancer.ServiceID { return loadbalancer.ServiceID(v.Key) }

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

var _ RevNatKey = (*RevNat4Key)(nil)
var _ RevNatValue = (*RevNat4Value)(nil)
var _ RevNatKey = (*RevNat6Key)(nil)
var _ RevNatValue = (*RevNat6Value)(nil)

//
// Affinity
//

const (
	AffinityMatchMapName = "cilium_lb_affinity_match"
	Affinity4MapName     = "cilium_lb4_affinity"
	Affinity6MapName     = "cilium_lb6_affinity"
)

type AffinityMatchKey struct {
	BackendID loadbalancer.BackendID `align:"backend_id"`
	RevNATID  uint16                 `align:"rev_nat_id"`
	Pad       uint16                 `align:"pad"`
}

type AffinityMatchValue struct {
	Pad uint8 `align:"pad"`
}

// String converts the key into a human readable string format
func (k *AffinityMatchKey) String() string {
	kHost := k.ToHost()
	return fmt.Sprintf("%d %d", kHost.BackendID, kHost.RevNATID)
}

func (k *AffinityMatchKey) New() bpf.MapKey { return &AffinityMatchKey{} }

// String converts the value into a human readable string format
func (v *AffinityMatchValue) String() string    { return "" }
func (v *AffinityMatchValue) New() bpf.MapValue { return &AffinityMatchValue{} }

// ToNetwork returns the key in the network byte order
func (k *AffinityMatchKey) ToNetwork() *AffinityMatchKey {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.RevNATID = byteorder.HostToNetwork16(n.RevNATID)
	return &n
}

// ToHost returns the key in the host byte order
func (k *AffinityMatchKey) ToHost() *AffinityMatchKey {
	h := *k
	h.RevNATID = byteorder.NetworkToHost16(h.RevNATID)
	return &h
}

// Affinity4Key is the Go representation of lb4_affinity_key
type Affinity4Key struct {
	ClientID    uint64 `align:"client_id"`
	RevNATID    uint16 `align:"rev_nat_id"`
	NetNSCookie uint8  `align:"netns_cookie"`
	Pad1        uint8  `align:"pad1"`
	Pad2        uint32 `align:"pad2"`
}

// Affinity6Key is the Go representation of lb6_affinity_key
type Affinity6Key struct {
	ClientID    types.IPv6 `align:"client_id"`
	RevNATID    uint16     `align:"rev_nat_id"`
	NetNSCookie uint8      `align:"netns_cookie"`
	Pad1        uint8      `align:"pad1"`
	Pad2        uint32     `align:"pad2"`
}

// AffinityValue is the Go representing of lb_affinity_value
type AffinityValue struct {
	LastUsed  uint64 `align:"last_used"`
	BackendID uint32 `align:"backend_id"`
	Pad       uint32 `align:"pad"`
}

// String converts the key into a human readable string format.
func (k *Affinity4Key) String() string {
	return fmt.Sprintf("%d %d %d", k.ClientID, k.NetNSCookie, k.RevNATID)
}

func (k *Affinity4Key) New() bpf.MapKey { return &Affinity4Key{} }

// String converts the key into a human readable string format.
func (k *Affinity6Key) String() string {
	return fmt.Sprintf("%d %d %d", k.ClientID, k.NetNSCookie, k.RevNATID)
}

func (k *Affinity6Key) New() bpf.MapKey { return &Affinity6Key{} }

// String converts the value into a human readable string format.
func (v *AffinityValue) String() string    { return fmt.Sprintf("%d %d", v.BackendID, v.LastUsed) }
func (v *AffinityValue) New() bpf.MapValue { return &AffinityValue{} }

//
// SockRevNat
//

const (
	// SockRevNat4MapName is the BPF map name.
	SockRevNat4MapName = "cilium_lb4_reverse_sk"

	// SockRevNat6MapName is the BPF map name.
	SockRevNat6MapName = "cilium_lb6_reverse_sk"

	// SockRevNat4MapSize is the maximum number of entries in the BPF map.
	SockRevNat4MapSize = 256 * 1024

	// SockRevNat6MapSize is the maximum number of entries in the BPF map.
	SockRevNat6MapSize = 256 * 1024

	// MaxSockRevNat4MapEntries is the maximum number of entries in the BPF
	// map. It is set by Init(), but unit tests use the initial value below.
	MaxSockRevNat4MapEntries = SockRevNat4MapSize

	// MaxSockRevNat6MapEntries is the maximum number of entries in the BPF
	// map. It is set by Init(), but unit tests use the initial value below.
	MaxSockRevNat6MapEntries = SockRevNat6MapSize
)

// SockRevNat4Key is the tuple with address, port and cookie used as key in
// the reverse NAT sock map.
type SockRevNat4Key struct {
	Cookie  uint64     `align:"cookie"`
	Address types.IPv4 `align:"address"`
	Port    int16      `align:"port"`
	_       int16
}

// SockRevNat4Value is an entry in the reverse NAT sock map.
type SockRevNat4Value struct {
	Address     types.IPv4 `align:"address"`
	Port        int16      `align:"port"`
	RevNatIndex uint16     `align:"rev_nat_index"`
}

func NewSockRevNat4Key(cookie uint64, addr net.IP, port uint16) *SockRevNat4Key {
	var key SockRevNat4Key
	key.Cookie = cookie
	key.Port = int16(byteorder.NetworkToHost16(port))
	copy(key.Address[:], addr.To4())

	return &key
}

// String converts the key into a human readable string format.
func (k *SockRevNat4Key) String() string {
	return fmt.Sprintf("[%s]:%d, %d", k.Address, k.Port, k.Cookie)
}

func (k *SockRevNat4Key) New() bpf.MapKey { return &SockRevNat4Key{} }

// String converts the value into a human readable string format.
func (v *SockRevNat4Value) String() string {
	return fmt.Sprintf("[%s]:%d, %d", v.Address, v.Port, v.RevNatIndex)
}

func (v *SockRevNat4Value) New() bpf.MapValue { return &SockRevNat4Value{} }

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
	Address     types.IPv6 `align:"address"`
	Port        int16      `align:"port"`
	RevNatIndex uint16     `align:"rev_nat_index"`
}

// SizeofSockRevNat6Value is the size of type SockRevNat6Value.
const SizeofSockRevNat6Value = int(unsafe.Sizeof(SockRevNat6Value{}))

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
	return fmt.Sprintf("[%s]:%d, %d", v.Address, v.Port, v.RevNatIndex)
}

func (v *SockRevNat6Value) New() bpf.MapValue { return &SockRevNat6Value{} }

//
// Maglev
//

const (
	// Both outer maps are pinned though given we need to insert
	// inner maps into them.
	MaglevOuter4MapName = "cilium_lb4_maglev"
	MaglevOuter6MapName = "cilium_lb6_maglev"

	MaglevInnerMapName = "cilium_maglev_inner"
)

// MaglevBackendLen represents the length of a single backend ID
// in a Maglev lookup table.
var MaglevBackendLen = uint32(unsafe.Sizeof(loadbalancer.BackendID(0)))

// MaglevOuterKey is the key of a maglev outer map.
type MaglevOuterKey struct {
	RevNatID uint16
}

// New and String implement bpf.MapKey
func (k *MaglevOuterKey) New() bpf.MapKey { return &MaglevOuterKey{} }
func (k *MaglevOuterKey) String() string  { return fmt.Sprintf("%d", k.RevNatID) }

var _ bpf.MapKey = &MaglevOuterKey{}

// toNetwork converts a maglev outer map's key to network byte order.
// The key is in network byte order in the eBPF maps.
func (k MaglevOuterKey) ToNetwork() MaglevOuterKey {
	return MaglevOuterKey{
		RevNatID: byteorder.HostToNetwork16(k.RevNatID),
	}
}

// MaglevOuterVal is the value of a maglev outer map.
type MaglevOuterVal struct {
	FD uint32
}

// New implements bpf.MapValue.
func (m *MaglevOuterVal) New() bpf.MapValue {
	return &MaglevOuterVal{}
}

// String implements bpf.MapValue.
func (m *MaglevOuterVal) String() string {
	return strconv.FormatUint(uint64(m.FD), 10)
}

// MaglevInnerKey is the key of a maglev inner map.
type MaglevInnerKey struct {
	Zero uint32
}

// New and String implement bpf.MapKey
func (k *MaglevInnerKey) New() bpf.MapKey { return &MaglevInnerKey{} }
func (k *MaglevInnerKey) String() string  { return fmt.Sprintf("%d", k.Zero) }

// MaglevInnerVal is the value of a maglev inner map.
type MaglevInnerVal struct {
	BackendIDs []loadbalancer.BackendID
}

//
// SourceRange
//

const (
	SourceRange4MapName = "cilium_lb4_source_range"
	SourceRange6MapName = "cilium_lb6_source_range"
	lpmPrefixLen4       = 16 + 16 // sizeof(SourceRangeKey4.RevNATID)+sizeof(SourceRangeKey4.Pad)
	lpmPrefixLen6       = 16 + 16 // sizeof(SourceRangeKey6.RevNATID)+sizeof(SourceRangeKey6.Pad)
)

type SourceRangeKey interface {
	bpf.MapKey

	GetCIDR() *cidr.CIDR
	GetRevNATID() loadbalancer.ServiceID

	// Convert fields to network byte order.
	ToNetwork() SourceRangeKey

	// ToHost converts fields to host byte order.
	ToHost() SourceRangeKey
}

// The compile-time check for whether the structs implement the interface
var _ SourceRangeKey = (*SourceRangeKey4)(nil)
var _ SourceRangeKey = (*SourceRangeKey6)(nil)

type SourceRangeKey4 struct {
	PrefixLen uint32     `align:"lpm_key"`
	RevNATID  uint16     `align:"rev_nat_id"`
	Pad       uint16     `align:"pad"`
	Address   types.IPv4 `align:"addr"`
}

func (k *SourceRangeKey4) String() string {
	kHost := k.ToHost().(*SourceRangeKey4)
	return fmt.Sprintf("%s (%d)", kHost.GetCIDR().String(), kHost.GetRevNATID())
}

func (k *SourceRangeKey4) New() bpf.MapKey { return &SourceRangeKey4{} }

func (k *SourceRangeKey4) ToNetwork() SourceRangeKey {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.RevNATID = byteorder.HostToNetwork16(n.RevNATID)
	return &n
}

// ToHost returns the key in the host byte order
func (k *SourceRangeKey4) ToHost() SourceRangeKey {
	h := *k
	h.RevNATID = byteorder.NetworkToHost16(h.RevNATID)
	return &h
}

func (k *SourceRangeKey4) GetCIDR() *cidr.CIDR {
	var (
		c  net.IPNet
		ip types.IPv4
	)
	c.Mask = net.CIDRMask(int(k.PrefixLen)-lpmPrefixLen4, 32)
	k.Address.DeepCopyInto(&ip)
	c.IP = ip.IP()
	return cidr.NewCIDR(&c)
}
func (k *SourceRangeKey4) GetRevNATID() loadbalancer.ServiceID {
	return loadbalancer.ServiceID(k.RevNATID)
}

type SourceRangeKey6 struct {
	PrefixLen uint32     `align:"lpm_key"`
	RevNATID  uint16     `align:"rev_nat_id"`
	Pad       uint16     `align:"pad"`
	Address   types.IPv6 `align:"addr"`
}

func (k *SourceRangeKey6) String() string {
	kHost := k.ToHost().(*SourceRangeKey6)
	return fmt.Sprintf("%s (%d)", kHost.GetCIDR().String(), kHost.GetRevNATID())
}

func (k *SourceRangeKey6) New() bpf.MapKey { return &SourceRangeKey6{} }

func (k *SourceRangeKey6) ToNetwork() SourceRangeKey {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.RevNATID = byteorder.HostToNetwork16(n.RevNATID)
	return &n
}

// ToHost returns the key in the host byte order
func (k *SourceRangeKey6) ToHost() SourceRangeKey {
	h := *k
	h.RevNATID = byteorder.NetworkToHost16(h.RevNATID)
	return &h
}

func (k *SourceRangeKey6) GetCIDR() *cidr.CIDR {
	var (
		c  net.IPNet
		ip types.IPv6
	)
	c.Mask = net.CIDRMask(int(k.PrefixLen)-lpmPrefixLen6, 128)
	k.Address.DeepCopyInto(&ip)
	c.IP = ip.IP()
	return cidr.NewCIDR(&c)
}
func (k *SourceRangeKey6) GetRevNATID() loadbalancer.ServiceID {
	return loadbalancer.ServiceID(k.RevNATID)
}

type SourceRangeValue struct {
	Pad uint8 // not used
}

func (v *SourceRangeValue) String() string    { return "" }
func (v *SourceRangeValue) New() bpf.MapValue { return &SourceRangeValue{} }

//
// Health probes
//

const (
	// HealthProbe4MapName is the health datapath map name
	HealthProbe4MapName = "cilium_lb4_health"

	// HealthProbe6MapName is the health datapath map name
	HealthProbe6MapName = "cilium_lb6_health"
)

//
// SkipLB
//

const (
	// SkipLB4MapName is the name of the IPv4 BPF map that stores entries to skip LB.
	SkipLB4MapName = "cilium_skip_lb4"

	// SkipLB6MapName is the name of the IPv6 BPF map that stores entries to skip LB.
	SkipLB6MapName = "cilium_skip_lb6"

	// SkipLBMapMaxEntries is the maximum number of entries in the skip LB BPF maps.
	SkipLBMapMaxEntries = 100
)

// SkipLB4Key is the tuple with netns cookie, address and port and used as key in
// the skip LB4 map.
type SkipLB4Key struct {
	NetnsCookie uint64     `align:"netns_cookie"`
	Address     types.IPv4 `align:"address"`
	Port        uint16     `align:"port"`
	Pad         int16      `align:"pad"`
}

type SkipLB4Value struct {
	Pad uint8 `align:"pad"`
}

// NewSkipLB4Key creates the SkipLB4Key
func NewSkipLB4Key(netnsCookie uint64, address net.IP, port uint16) *SkipLB4Key {
	key := SkipLB4Key{
		NetnsCookie: netnsCookie,
		Port:        byteorder.HostToNetwork16(port),
	}
	copy(key.Address[:], address.To4())

	return &key
}

func (k *SkipLB4Key) New() bpf.MapKey { return &SkipLB4Key{} }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *SkipLB4Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human-readable string format.
func (k *SkipLB4Key) String() string {
	return fmt.Sprintf("[%d]:%d, %d", k.NetnsCookie, k.Address, k.Port)
}

func (v *SkipLB4Value) New() bpf.MapValue { return &SkipLB4Value{} }

// String converts the value into a human-readable string format.
func (v *SkipLB4Value) String() string {
	return ""
}

// SkipLB6Key is the tuple with netns cookie, address and port and used as key in
// the skip LB6 map.
type SkipLB6Key struct {
	NetnsCookie uint64     `align:"netns_cookie"`
	Address     types.IPv6 `align:"address"`
	Pad         uint32     `align:"pad"`
	Port        uint16     `align:"port"`
	Pad2        uint16     `align:"pad2"`
}

type SkipLB6Value struct {
	Pad uint8 `align:"pad"`
}

// NewSkipLB6Key creates the SkipLB6Key
func NewSkipLB6Key(netnsCookie uint64, address net.IP, port uint16) *SkipLB6Key {
	key := SkipLB6Key{
		NetnsCookie: netnsCookie,
		Port:        byteorder.HostToNetwork16(port),
	}
	copy(key.Address[:], address.To16())

	return &key
}

func (k *SkipLB6Key) New() bpf.MapKey { return &SkipLB6Key{} }

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *SkipLB6Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *SkipLB6Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human-readable string format.
func (k *SkipLB6Key) String() string {
	return fmt.Sprintf("[%d]:%d, %d", k.NetnsCookie, k.Address, k.Port)
}

func (v *SkipLB6Value) New() bpf.MapValue { return &SkipLB6Value{} }

// String converts the value into a human-readable string format.
func (v *SkipLB6Value) String() string {
	return ""
}

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k *SkipLB6Key) NewValue() bpf.MapValue { return &SkipLB6Value{} }

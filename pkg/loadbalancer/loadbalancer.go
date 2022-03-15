// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
)

// SVCType is a type of a service.
type SVCType string

const (
	SVCTypeNone          = SVCType("NONE")
	SVCTypeHostPort      = SVCType("HostPort")
	SVCTypeClusterIP     = SVCType("ClusterIP")
	SVCTypeNodePort      = SVCType("NodePort")
	SVCTypeExternalIPs   = SVCType("ExternalIPs")
	SVCTypeLoadBalancer  = SVCType("LoadBalancer")
	SVCTypeLocalRedirect = SVCType("LocalRedirect")
)

// SVCTrafficPolicy defines which backends are chosen
type SVCTrafficPolicy string

const (
	SVCTrafficPolicyNone    = SVCTrafficPolicy("NONE")
	SVCTrafficPolicyCluster = SVCTrafficPolicy("Cluster")
	SVCTrafficPolicyLocal   = SVCTrafficPolicy("Local")
)

// SVCNatPolicy defines whether we need NAT46/64 translation for backends
type SVCNatPolicy string

const (
	SVCNatPolicyNone  = SVCNatPolicy("NONE")
	SVCNatPolicyNat46 = SVCNatPolicy("Nat46")
	SVCNatPolicyNat64 = SVCNatPolicy("Nat64")
)

// ServiceFlags is the datapath representation of the service flags that can be
// used (lb{4,6}_service.flags)
type ServiceFlags uint16

const (
	serviceFlagNone            = 0
	serviceFlagExternalIPs     = 1 << 0
	serviceFlagNodePort        = 1 << 1
	serviceFlagLocalScope      = 1 << 2
	serviceFlagHostPort        = 1 << 3
	serviceFlagSessionAffinity = 1 << 4
	serviceFlagLoadBalancer    = 1 << 5
	serviceFlagRoutable        = 1 << 6
	serviceFlagSourceRange     = 1 << 7
	serviceFlagLocalRedirect   = 1 << 8
	serviceFlagNat46x64        = 1 << 9
	serviceFlagL7LoadBalancer  = 1 << 10
)

type SvcFlagParam struct {
	SvcType          SVCType
	SvcNatPolicy     SVCNatPolicy
	SvcLocal         bool
	SessionAffinity  bool
	IsRoutable       bool
	CheckSourceRange bool
	L7LoadBalancer   bool
}

// NewSvcFlag creates service flag
func NewSvcFlag(p *SvcFlagParam) ServiceFlags {
	var flags ServiceFlags

	switch p.SvcType {
	case SVCTypeExternalIPs:
		flags |= serviceFlagExternalIPs
	case SVCTypeNodePort:
		flags |= serviceFlagNodePort
	case SVCTypeLoadBalancer:
		flags |= serviceFlagLoadBalancer
	case SVCTypeHostPort:
		flags |= serviceFlagHostPort
	case SVCTypeLocalRedirect:
		flags |= serviceFlagLocalRedirect
	}

	switch p.SvcNatPolicy {
	case SVCNatPolicyNat46:
		fallthrough
	case SVCNatPolicyNat64:
		flags |= serviceFlagNat46x64
	}

	if p.SvcLocal {
		flags |= serviceFlagLocalScope
	}
	if p.SessionAffinity {
		flags |= serviceFlagSessionAffinity
	}
	if p.IsRoutable {
		flags |= serviceFlagRoutable
	}
	if p.CheckSourceRange {
		flags |= serviceFlagSourceRange
	}
	if p.L7LoadBalancer {
		flags |= serviceFlagL7LoadBalancer
	}

	return flags
}

// SVCType returns a service type from the flags
func (s ServiceFlags) SVCType() SVCType {
	switch {
	case s&serviceFlagExternalIPs != 0:
		return SVCTypeExternalIPs
	case s&serviceFlagNodePort != 0:
		return SVCTypeNodePort
	case s&serviceFlagLoadBalancer != 0:
		return SVCTypeLoadBalancer
	case s&serviceFlagHostPort != 0:
		return SVCTypeHostPort
	case s&serviceFlagLocalRedirect != 0:
		return SVCTypeLocalRedirect
	default:
		return SVCTypeClusterIP
	}
}

// SVCTrafficPolicy returns a service traffic policy from the flags
func (s ServiceFlags) SVCTrafficPolicy() SVCTrafficPolicy {
	switch {
	case s&serviceFlagLocalScope != 0:
		return SVCTrafficPolicyLocal
	default:
		return SVCTrafficPolicyCluster
	}
}

// SVCNatPolicy returns a service NAT policy from the flags
func (s ServiceFlags) SVCNatPolicy(fe L3n4Addr) SVCNatPolicy {
	if s&serviceFlagNat46x64 == 0 {
		return SVCNatPolicyNone
	}

	if fe.IsIPv6() {
		return SVCNatPolicyNat64
	} else {
		return SVCNatPolicyNat46
	}
}

// String returns the string implementation of ServiceFlags.
func (s ServiceFlags) String() string {
	var str []string

	str = append(str, string(s.SVCType()))
	if s&serviceFlagLocalScope != 0 {
		str = append(str, string(SVCTrafficPolicyLocal))
	}
	if s&serviceFlagSessionAffinity != 0 {
		str = append(str, "sessionAffinity")
	}
	if s&serviceFlagRoutable == 0 {
		str = append(str, "non-routable")
	}
	if s&serviceFlagSourceRange != 0 {
		str = append(str, "check source-range")
	}
	if s&serviceFlagNat46x64 != 0 {
		str = append(str, "46x64")
	}
	if s&serviceFlagL7LoadBalancer != 0 {
		str = append(str, "l7-load-balancer")
	}

	return strings.Join(str, ", ")
}

// UInt8 returns the UInt16 representation of the ServiceFlags.
func (s ServiceFlags) UInt16() uint16 {
	return uint16(s)
}

const (
	NONE = L4Type("NONE")
	// TCP type.
	TCP = L4Type("TCP")
	// UDP type.
	UDP = L4Type("UDP")
)

const (
	// ScopeExternal is the lookup scope for services from outside the node.
	ScopeExternal uint8 = iota
	// ScopeInternal is the lookup scope for services from inside the node.
	ScopeInternal
)

// BackendState tracks backend's ability to load-balance service traffic.
//
// Valid transition states for a backend -
// BackendStateActive -> BackendStateTerminating, BackendStateQuarantined, BackendStateMaintenance
// BackendStateTerminating -> No valid state transition
// BackendStateQuarantined -> BackendStateActive, BackendStateTerminating
// BackendStateMaintenance -> BackendStateActive
//
// Sources setting the states -
// BackendStateActive - Kubernetes events, service API
// BackendStateTerminating - Kubernetes events
// BackendStateQuarantined - service API
// BackendStateMaintenance - service API
const (
	// BackendStateActive refers to the backend state when it's available for
	// load-balancing traffic. It's the default state for a backend.
	// Backends in this state can be health-checked.
	BackendStateActive BackendState = iota
	// BackendStateTerminating refers to the terminating backend state so that
	// it can be gracefully removed.
	// Backends in this state won't be health-checked.
	BackendStateTerminating
	// BackendStateQuarantined refers to the backend state when it's unreachable,
	// and will not be selected for load-balancing traffic.
	// Backends in this state can be health-checked.
	BackendStateQuarantined
	// BackendStateMaintenance refers to the backend state where the backend
	// is put under maintenance, and will neither be selected for load-balancing
	// traffic nor be health-checked.
	BackendStateMaintenance
	// BackendStateInvalid is an invalid state, and is used to report error conditions.
	// Keep this as the last entry.
	BackendStateInvalid
)

// BackendStateFlags is the datapath representation of the backend flags that
// are used in (lb{4,6}_backend.flags) to store backend state.
type BackendStateFlags = uint8

const (
	BackendStateActiveFlag = iota
	BackendStateTerminatingFlag
	BackendStateQuarantinedFlag
	BackendStateMaintenanceFlag
)

func NewBackendFlags(state BackendState) BackendStateFlags {
	var flags BackendStateFlags

	switch state {
	case BackendStateActive:
		flags = BackendStateActiveFlag
	case BackendStateTerminating:
		flags = BackendStateTerminatingFlag
	case BackendStateQuarantined:
		flags = BackendStateQuarantinedFlag
	case BackendStateMaintenance:
		flags = BackendStateMaintenanceFlag
	}

	return flags
}

func GetBackendStateFromFlags(flags uint8) BackendState {
	switch flags {
	case BackendStateTerminatingFlag:
		return BackendStateTerminating
	case BackendStateQuarantinedFlag:
		return BackendStateQuarantined
	case BackendStateMaintenanceFlag:
		return BackendStateMaintenance
	default:
		return BackendStateActive
	}
}

var (
	// AllProtocols is the list of all supported L4 protocols
	AllProtocols = []L4Type{TCP, UDP}
)

// L4Type name.
type L4Type = string

// FEPortName is the name of the frontend's port.
type FEPortName string

// ServiceID is the service's ID.
type ServiceID uint16

// BackendID is the backend's ID.
type BackendID uint32

// ID is the ID of L3n4Addr endpoint (either service or backend).
type ID uint32

// BackendState is the state of a backend for load-balancing service traffic.
type BackendState uint8

// Backend represents load balancer backend.
type Backend struct {
	// ID of the backend
	ID BackendID
	// Node hosting this backend. This is used to determine backends local to
	// a node.
	NodeName string
	L3n4Addr
	// State of the backend for load-balancing service traffic
	State BackendState
	// RestoredFromDatapath indicates whether the backend was restored from BPF maps
	RestoredFromDatapath bool
}

func (b *Backend) String() string {
	return b.L3n4Addr.String()
}

// SVC is a structure for storing service details.
type SVC struct {
	Frontend                  L3n4AddrID       // SVC frontend addr and an allocated ID
	Backends                  []Backend        // List of service backends
	Type                      SVCType          // Service type
	TrafficPolicy             SVCTrafficPolicy // Service traffic policy
	NatPolicy                 SVCNatPolicy     // Service NAT 46/64 policy
	SessionAffinity           bool
	SessionAffinityTimeoutSec uint32
	HealthCheckNodePort       uint16 // Service health check node port
	Name                      string // Service name
	Namespace                 string // Service namespace
	LoadBalancerSourceRanges  []*cidr.CIDR
	L7LBProxyPort             uint16 // Non-zero for L7 LB services
}

func (s *SVC) GetModel() *models.Service {
	var natPolicy string
	type backendPlacement struct {
		pos int
		id  BackendID
	}

	if s == nil {
		return nil
	}

	id := int64(s.Frontend.ID)
	if s.NatPolicy != SVCNatPolicyNone {
		natPolicy = string(s.NatPolicy)
	}
	spec := &models.ServiceSpec{
		ID:               id,
		FrontendAddress:  s.Frontend.GetModel(),
		BackendAddresses: make([]*models.BackendAddress, len(s.Backends)),
		Flags: &models.ServiceSpecFlags{
			Type:                string(s.Type),
			TrafficPolicy:       string(s.TrafficPolicy),
			NatPolicy:           natPolicy,
			HealthCheckNodePort: s.HealthCheckNodePort,

			Name:      s.Name,
			Namespace: s.Namespace,
		},
	}

	placements := make([]backendPlacement, len(s.Backends))
	for i, be := range s.Backends {
		placements[i] = backendPlacement{pos: i, id: be.ID}
	}
	sort.Slice(placements,
		func(i, j int) bool { return placements[i].id < placements[j].id })
	for i, placement := range placements {
		spec.BackendAddresses[i] = s.Backends[placement.pos].GetBackendModel()
	}

	return &models.Service{
		Spec: spec,
		Status: &models.ServiceStatus{
			Realized: spec,
		},
	}
}

func IsValidStateTransition(old, new BackendState) bool {
	if old == new {
		return true
	}
	if new == BackendStateInvalid {
		return false
	}

	switch old {
	case BackendStateActive:
	case BackendStateTerminating:
		return false
	case BackendStateQuarantined:
		if new == BackendStateMaintenance {
			return false
		}
	case BackendStateMaintenance:
		if new != BackendStateActive {
			return false
		}
	default:
		return false
	}
	return true
}

func GetBackendState(state string) (BackendState, error) {
	switch strings.ToLower(state) {
	case "active", "":
		return BackendStateActive, nil
	case "terminating":
		return BackendStateTerminating, nil
	case "quarantined":
		return BackendStateQuarantined, nil
	case "maintenance":
		return BackendStateMaintenance, nil
	default:
		return BackendStateInvalid, fmt.Errorf("invalid backend state %s", state)
	}
}

func (state BackendState) String() (string, error) {
	switch state {
	case BackendStateActive:
		return "active", nil
	case BackendStateTerminating:
		return "terminating", nil
	case BackendStateQuarantined:
		return "quarantined", nil
	case BackendStateMaintenance:
		return "maintenance", nil
	default:
		return "", fmt.Errorf("invalid backend state %d", state)
	}
}

func IsValidBackendState(state string) bool {
	_, err := GetBackendState(state)

	return err == nil
}

func NewL4Type(name string) (L4Type, error) {
	switch strings.ToLower(name) {
	case "tcp":
		return TCP, nil
	case "udp":
		return UDP, nil
	default:
		return "", fmt.Errorf("unknown L4 protocol")
	}
}

// L4Addr is an abstraction for the backend port with a L4Type, usually tcp or udp, and
// the Port number.
//
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type L4Addr struct {
	Protocol L4Type
	Port     uint16
}

// DeepEqual returns true if both the receiver and 'o' are deeply equal.
func (l *L4Addr) DeepEqual(o *L4Addr) bool {
	if l == nil {
		return o == nil
	}
	return l.deepEqual(o)
}

// NewL4Addr creates a new L4Addr.
func NewL4Addr(protocol L4Type, number uint16) *L4Addr {
	return &L4Addr{Protocol: protocol, Port: number}
}

// L3n4Addr is used to store, as an unique L3+L4 address in the KVStore. It also
// includes the lookup scope for frontend addresses which is used in service
// handling for externalTrafficPolicy=Local, that is, Scope{External,Internal}.
//
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type L3n4Addr struct {
	// +deepequal-gen=false
	IP net.IP
	L4Addr
	Scope uint8
}

// DeepEqual returns true if both the receiver and 'o' are deeply equal.
func (l *L3n4Addr) DeepEqual(o *L3n4Addr) bool {
	if l == nil {
		return o == nil
	}
	return l.IP.Equal(o.IP) && l.deepEqual(o)
}

// NewL3n4Addr creates a new L3n4Addr.
func NewL3n4Addr(protocol L4Type, ip net.IP, portNumber uint16, scope uint8) *L3n4Addr {
	lbport := NewL4Addr(protocol, portNumber)

	addr := L3n4Addr{IP: ip, L4Addr: *lbport, Scope: scope}

	return &addr
}

func NewL3n4AddrFromModel(base *models.FrontendAddress) (*L3n4Addr, error) {
	var scope uint8

	if base == nil {
		return nil, nil
	}

	if base.IP == "" {
		return nil, fmt.Errorf("missing IP address")
	}

	proto := NONE
	if base.Protocol != "" {
		p, err := NewL4Type(base.Protocol)
		if err != nil {
			return nil, err
		}
		proto = p
	}

	l4addr := NewL4Addr(proto, base.Port)
	ip := net.ParseIP(base.IP)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address \"%s\"", base.IP)
	}

	if base.Scope == models.FrontendAddressScopeExternal {
		scope = ScopeExternal
	} else if base.Scope == models.FrontendAddressScopeInternal {
		scope = ScopeInternal
	} else {
		return nil, fmt.Errorf("invalid scope \"%s\"", base.Scope)
	}

	return &L3n4Addr{IP: ip, L4Addr: *l4addr, Scope: scope}, nil
}

// NewBackend creates the Backend struct instance from given params.
// The default state for the returned Backend is BackendStateActive.
func NewBackend(id BackendID, protocol L4Type, ip net.IP, portNumber uint16) *Backend {
	lbport := NewL4Addr(protocol, portNumber)
	b := Backend{
		ID:       BackendID(id),
		L3n4Addr: L3n4Addr{IP: ip, L4Addr: *lbport},
		State:    BackendStateActive,
	}

	return &b
}

// NewBackendWithState creates the Backend struct instance from given params,
// and sets the restore state for the Backend.
func NewBackendWithState(id BackendID, protocol L4Type, ip net.IP, portNumber uint16,
	state BackendState, restored bool) *Backend {
	lbport := NewL4Addr(protocol, portNumber)
	b := Backend{
		ID:                   id,
		L3n4Addr:             L3n4Addr{IP: ip, L4Addr: *lbport},
		State:                state,
		RestoredFromDatapath: restored,
	}

	return &b
}

func NewBackendFromBackendModel(base *models.BackendAddress) (*Backend, error) {
	if base.IP == nil {
		return nil, fmt.Errorf("missing IP address")
	}

	// FIXME: Should this be NONE ?
	l4addr := NewL4Addr(NONE, base.Port)
	ip := net.ParseIP(*base.IP)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address \"%s\"", *base.IP)
	}
	state, err := GetBackendState(base.State)
	if err != nil {
		return nil, fmt.Errorf("invalid backend state [%s]", base.State)
	}

	return &Backend{NodeName: base.NodeName, L3n4Addr: L3n4Addr{IP: ip, L4Addr: *l4addr}, State: state}, nil
}

func NewL3n4AddrFromBackendModel(base *models.BackendAddress) (*L3n4Addr, error) {
	if base.IP == nil {
		return nil, fmt.Errorf("missing IP address")
	}

	// FIXME: Should this be NONE ?
	l4addr := NewL4Addr(NONE, base.Port)
	ip := net.ParseIP(*base.IP)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address \"%s\"", *base.IP)
	}
	return &L3n4Addr{IP: ip, L4Addr: *l4addr}, nil
}

func (a *L3n4Addr) GetModel() *models.FrontendAddress {
	if a == nil {
		return nil
	}

	scope := models.FrontendAddressScopeExternal
	if a.Scope == ScopeInternal {
		scope = models.FrontendAddressScopeInternal
	}
	return &models.FrontendAddress{
		IP:    a.IP.String(),
		Port:  a.Port,
		Scope: scope,
	}
}

func (b *Backend) GetBackendModel() *models.BackendAddress {
	if b == nil {
		return nil
	}

	ip := b.IP.String()
	stateStr, _ := b.State.String()
	return &models.BackendAddress{
		IP:       &ip,
		Port:     b.Port,
		NodeName: b.NodeName,
		State:    stateStr,
	}
}

// String returns the L3n4Addr in the "IPv4:Port[/Scope]" format for IPv4 and
// "[IPv6]:Port[/Scope]" format for IPv6.
func (a *L3n4Addr) String() string {
	var scope string
	if a.Scope == ScopeInternal {
		scope = "/i"
	}
	if a.IsIPv6() {
		return fmt.Sprintf("[%s]:%d%s", a.IP.String(), a.Port, scope)
	}
	return fmt.Sprintf("%s:%d%s", a.IP.String(), a.Port, scope)
}

// StringWithProtocol returns the L3n4Addr in the "IPv4:Port/Protocol[/Scope]"
// format for IPv4 and "[IPv6]:Port/Protocol[/Scope]" format for IPv6.
func (a *L3n4Addr) StringWithProtocol() string {
	var scope string
	if a.Scope == ScopeInternal {
		scope = "/i"
	}
	if a.IsIPv6() {
		return fmt.Sprintf("[%s]:%d/%s%s", a.IP.String(), a.Port, a.Protocol, scope)
	}
	return fmt.Sprintf("%s:%d/%s%s", a.IP.String(), a.Port, a.Protocol, scope)
}

// StringID returns the L3n4Addr as string to be used for unique identification
func (a *L3n4Addr) StringID() string {
	// This does not include the protocol right now as the datapath does
	// not include the protocol in the lookup of the service IP.
	return a.String()
}

// Hash calculates a unique string of the L3n4Addr e.g for use as a key in maps.
// Note: the resulting string is meant to be used as a key for maps and is not
// readable by a human eye when printed out.
func (a L3n4Addr) Hash() string {
	const lenProto = 0 // proto is omitted for now
	const lenScope = 1 // scope is uint8 which is an alias for byte
	const lenPort = 2  // port is uint16 which is 2 bytes

	b := make([]byte, net.IPv6len+lenProto+lenScope+lenPort)
	copy(b, a.IP.To16())
	// FIXME: add Protocol once we care about protocols
	// scope is a uint8 which is an alias for byte so a cast is safe
	b[net.IPv6len+lenProto] = byte(a.Scope)
	// port is a uint16, so 2 bytes
	b[net.IPv6len+lenProto+lenScope] = byte(a.Port >> 8)
	b[net.IPv6len+lenProto+lenScope+1] = byte(a.Port & 0xff)
	return string(b)
}

// IsIPv6 returns true if the IP address in the given L3n4Addr is IPv6 or not.
func (a *L3n4Addr) IsIPv6() bool {
	return a.IP.To4() == nil
}

// L3n4AddrID is used to store, as an unique L3+L4 plus the assigned ID, in the
// KVStore.
//
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type L3n4AddrID struct {
	L3n4Addr
	ID ID
}

// DeepEqual returns true if both the receiver and 'o' are deeply equal.
func (l *L3n4AddrID) DeepEqual(o *L3n4AddrID) bool {
	if l == nil {
		return o == nil
	}
	return l.deepEqual(o)
}

// NewL3n4AddrID creates a new L3n4AddrID.
func NewL3n4AddrID(protocol L4Type, ip net.IP, portNumber uint16, scope uint8, id ID) *L3n4AddrID {
	l3n4Addr := NewL3n4Addr(protocol, ip, portNumber, scope)
	return &L3n4AddrID{L3n4Addr: *l3n4Addr, ID: id}
}

// IsIPv6 returns true if the IP address in L3n4Addr's L3n4AddrID is IPv6 or not.
func (l *L3n4AddrID) IsIPv6() bool {
	return l.L3n4Addr.IsIPv6()
}

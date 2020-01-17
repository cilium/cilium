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

package loadbalancer

import (
	"crypto/sha512"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "loadbalancer")
)

// SVCType is a type of a service.
type SVCType string

const (
	SVCTypeNone         = SVCType("NONE")
	SVCTypeClusterIP    = SVCType("ClusterIP")
	SVCTypeNodePort     = SVCType("NodePort")
	SVCTypeExternalIPs  = SVCType("ExternalIPs")
	SVCTypeLoadBalancer = SVCType("LoadBalancer")
)

// SVCTrafficPolicy defines which backends are chosen
type SVCTrafficPolicy string

const (
	SVCTrafficPolicyNone    = SVCTrafficPolicy("NONE")
	SVCTrafficPolicyCluster = SVCTrafficPolicy("Cluster")
	SVCTrafficPolicyLocal   = SVCTrafficPolicy("Local")
)

// ServiceFlags is the datapath representation of the service flags that can be
// used.
type ServiceFlags uint8

const (
	serviceFlagNone        = 0
	serviceFlagExternalIPs = 1
	serviceFlagNodePort    = 2
)

// CreateSvcFlag returns the ServiceFlags for all given SVCTypes.
func CreateSvcFlag(svcTypes ...SVCType) ServiceFlags {
	var flags ServiceFlags
	for _, svcType := range svcTypes {
		switch svcType {
		case SVCTypeExternalIPs:
			flags |= serviceFlagExternalIPs
		case SVCTypeNodePort:
			flags |= serviceFlagNodePort
		}
	}
	return flags
}

// IsSvcType returns true if the serviceFlags is the given SVCType.
func (s ServiceFlags) IsSvcType(svcType SVCType) bool {
	return s&CreateSvcFlag(svcType) != 0
}

// ServiceFlags returns a service type from the flags
func (s ServiceFlags) SVCType() SVCType {
	switch {
	case s&serviceFlagExternalIPs != 0:
		return SVCTypeExternalIPs
	case s&serviceFlagNodePort != 0:
		return SVCTypeNodePort
	default:
		return SVCTypeClusterIP
	}
}

// String returns the string implementation of ServiceFlags.
func (s ServiceFlags) String() string {
	var strTypes []string
	typeSet := false
	for _, svcType := range []SVCType{SVCTypeExternalIPs, SVCTypeNodePort} {
		if s.IsSvcType(svcType) {
			strTypes = append(strTypes, string(svcType))
			typeSet = true
		}
	}
	if !typeSet {
		strTypes = append(strTypes, string(SVCTypeClusterIP))
	}
	return strings.Join(strTypes, ", ")
}

// UInt8 returns the UInt8 representation of the ServiceFlags.
func (s ServiceFlags) UInt8() uint8 {
	return uint8(s)
}

const (
	NONE = L4Type("NONE")
	// TCP type.
	TCP = L4Type("TCP")
	// UDP type.
	UDP = L4Type("UDP")
)

var (
	// AllProtocols is the list of all supported L4 protocols
	AllProtocols = []L4Type{TCP, UDP}
)

// L4Type name.
type L4Type string

// FEPortName is the name of the frontend's port.
type FEPortName string

// ServiceID is the service's ID.
type ServiceID uint16

// BackendID is the backend's ID.
type BackendID uint16

// ID is the ID of L3n4Addr endpoint (either service or backend).
type ID uint32

// Backend represents load balancer backend.
type Backend struct {
	// ID of the backend
	ID BackendID
	// Node hosting this backend. This is used to determine backends local to
	// a node.
	NodeName string
	L3n4Addr
}

func (b *Backend) String() string {
	return b.L3n4Addr.String()
}

// SVC is a structure for storing service details.
type SVC struct {
	Frontend      L3n4AddrID       // SVC frontend addr and an allocated ID
	Backends      []Backend        // List of service backends
	Type          SVCType          // Service type
	TrafficPolicy SVCTrafficPolicy // Service traffic policy
	Name          string           // Service name
	Namespace     string           // Service namespace
}

func (s *SVC) GetModel() *models.Service {
	type backendPlacement struct {
		pos int
		id  BackendID
	}

	if s == nil {
		return nil
	}

	id := int64(s.Frontend.ID)
	spec := &models.ServiceSpec{
		ID:               id,
		FrontendAddress:  s.Frontend.GetModel(),
		BackendAddresses: make([]*models.BackendAddress, len(s.Backends)),
		Flags: &models.ServiceSpecFlags{
			Type:          string(s.Type),
			TrafficPolicy: string(s.TrafficPolicy),
			Name:          s.Name,
			Namespace:     s.Namespace,
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
type L4Addr struct {
	Protocol L4Type
	Port     uint16
}

// NewL4Addr creates a new L4Addr.
func NewL4Addr(protocol L4Type, number uint16) *L4Addr {
	return &L4Addr{Protocol: protocol, Port: number}
}

// Equals returns true if both L4Addr are considered equal.
func (l *L4Addr) Equals(o *L4Addr) bool {
	switch {
	case (l == nil) != (o == nil):
		return false
	case (l == nil) && (o == nil):
		return true
	}
	return l.Port == o.Port && l.Protocol == o.Protocol
}

// DeepCopy returns a DeepCopy of the given L4Addr.
func (l *L4Addr) DeepCopy() *L4Addr {
	return &L4Addr{
		Port:     l.Port,
		Protocol: l.Protocol,
	}
}

// L3n4Addr is used to store, as an unique L3+L4 address in the KVStore.
type L3n4Addr struct {
	IP net.IP
	L4Addr
}

// NewL3n4Addr creates a new L3n4Addr.
func NewL3n4Addr(protocol L4Type, ip net.IP, portNumber uint16) *L3n4Addr {
	lbport := NewL4Addr(protocol, portNumber)

	addr := L3n4Addr{IP: ip, L4Addr: *lbport}
	log.WithField(logfields.IPAddr, addr).Debug("created new L3n4Addr")

	return &addr
}

func NewL3n4AddrFromModel(base *models.FrontendAddress) (*L3n4Addr, error) {
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

	return &L3n4Addr{IP: ip, L4Addr: *l4addr}, nil
}

// NewBackend creates the Backend struct instance from given params.
func NewBackend(id BackendID, protocol L4Type, ip net.IP, portNumber uint16) *Backend {
	lbport := NewL4Addr(protocol, portNumber)
	b := Backend{
		ID:       BackendID(id),
		L3n4Addr: L3n4Addr{IP: ip, L4Addr: *lbport},
	}
	log.WithField("backend", b).Debug("created new LBBackend")

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

	return &Backend{NodeName: base.NodeName, L3n4Addr: L3n4Addr{IP: ip, L4Addr: *l4addr}}, nil
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

	return &models.FrontendAddress{
		IP:   a.IP.String(),
		Port: a.Port,
	}
}

func (b *Backend) GetBackendModel() *models.BackendAddress {
	if b == nil {
		return nil
	}

	ip := b.IP.String()
	return &models.BackendAddress{
		IP:       &ip,
		Port:     b.Port,
		NodeName: b.NodeName,
	}
}

// String returns the L3n4Addr in the "IPv4:Port" format for IPv4 and
// "[IPv6]:Port" format for IPv6.
func (a *L3n4Addr) String() string {
	if a.IsIPv6() {
		return fmt.Sprintf("[%s]:%d", a.IP.String(), a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
}

// StringWithProtocol returns the L3n4Addr in the "IPv4:Port/Protocol" format
// for IPv4 and "[IPv6]:Port/Protocol" format for IPv6.
func (a *L3n4Addr) StringWithProtocol() string {
	if a.IsIPv6() {
		return fmt.Sprintf("[%s]:%d/%s", a.IP.String(), a.Port, a.Protocol)
	}
	return fmt.Sprintf("%s:%d/%s", a.IP.String(), a.Port, a.Protocol)
}

// StringID returns the L3n4Addr as string to be used for unique identification
func (a *L3n4Addr) StringID() string {
	// This does not include the protocol right now as the datapath does
	// not include the protocol in the lookup of the service IP.
	return a.String()
}

// DeepCopy returns a DeepCopy of the given L3n4Addr.
func (a *L3n4Addr) DeepCopy() *L3n4Addr {
	copyIP := make(net.IP, len(a.IP))
	copy(copyIP, a.IP)
	return &L3n4Addr{
		IP:     copyIP,
		L4Addr: *a.L4Addr.DeepCopy(),
	}
}

// Hash calculates L3n4Addr's internal SHA256Sum.
func (a L3n4Addr) Hash() string {
	// FIXME: Remove Protocol's omission once we care about protocols.
	protoBak := a.Protocol
	a.Protocol = ""
	defer func() {
		a.Protocol = protoBak
	}()

	str := []byte(fmt.Sprintf("%+v", a))
	return fmt.Sprintf("%x", sha512.Sum512_256(str))
}

// IsIPv6 returns true if the IP address in the given L3n4Addr is IPv6 or not.
func (a *L3n4Addr) IsIPv6() bool {
	return a.IP.To4() == nil
}

// L3n4AddrID is used to store, as an unique L3+L4 plus the assigned ID, in the
// KVStore.
type L3n4AddrID struct {
	L3n4Addr
	ID ID
}

// NewL3n4AddrID creates a new L3n4AddrID.
func NewL3n4AddrID(protocol L4Type, ip net.IP, portNumber uint16, id ID) *L3n4AddrID {
	l3n4Addr := NewL3n4Addr(protocol, ip, portNumber)
	return &L3n4AddrID{L3n4Addr: *l3n4Addr, ID: id}
}

// IsIPv6 returns true if the IP address in L3n4Addr's L3n4AddrID is IPv6 or not.
func (l *L3n4AddrID) IsIPv6() bool {
	return l.L3n4Addr.IsIPv6()
}

// Equals checks equality of both given addresses.
func (l *L3n4AddrID) Equals(o *L3n4AddrID) bool {
	switch {
	case (l == nil) != (o == nil):
		return false
	case (l == nil) && (o == nil):
		return true
	}

	if l.ID != o.ID {
		return false
	}
	if !l.IP.Equal(o.IP) {
		return false
	}
	if !l.L4Addr.Equals(&o.L4Addr) {
		return false
	}

	return true
}

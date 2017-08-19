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

package types

import (
	"crypto/sha512"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cilium/cilium/api/v1/models"
)

const (
	NONE = L4Type("NONE")
	// TCP type.
	TCP = L4Type("TCP")
	// UDP type.
	UDP = L4Type("UDP")
)

// L4Type name.
type L4Type string

// FEPortName is the name of the frontend's port.
type FEPortName string

// ServiceID is the service's ID.
type ServiceID uint16

// LBBackEnd represents load balancer backend.
type LBBackEnd struct {
	L3n4Addr
	Weight uint16
}

// LBSVC is essentially used for the REST API.
type LBSVC struct {
	Sha256 string
	FE     L3n4AddrID
	BES    []LBBackEnd
}

func (s *LBSVC) GetModel() *models.Service {
	if s == nil {
		return nil
	}

	id := int64(s.FE.ID)
	svc := &models.Service{
		ID:               id,
		FrontendAddress:  s.FE.GetModel(),
		BackendAddresses: make([]*models.BackendAddress, len(s.BES)),
	}

	for i, be := range s.BES {
		svc.BackendAddresses[i] = be.GetBackendModel()
	}

	return svc
}

// SVCMap is a map of the daemon's services. The key is the sha256sum of the LBSVC's FE
// and the value the LBSVC.
type SVCMap map[string]LBSVC

// SVCMapID maps service IDs to service structures.
type SVCMapID map[ServiceID]*LBSVC

// RevNATMap is a map of the daemon's RevNATs.
type RevNATMap map[ServiceID]L3n4Addr

// K8sServiceList is a list of services derived from k8s specs
type K8sServiceList []*K8sServiceInfo

// LoadBalancer is the internal representation of the loadbalancer in the local cilium
// daemon.
type LoadBalancer struct {
	BPFMapMU  sync.RWMutex
	SVCMap    SVCMap
	SVCMapID  SVCMapID
	RevNATMap RevNATMap

	K8sMU        sync.Mutex
	K8sServices  map[K8sServiceNamespace]K8sServiceList
	K8sEndpoints map[K8sServiceNamespace]*K8sServiceEndpoint
	K8sIngress   map[K8sServiceNamespace]*K8sServiceInfo
}

// AddService adds a service to list of loadbalancers and returns true if created.
func (lb *LoadBalancer) AddService(svc LBSVC) bool {
	oldSvc, ok := lb.SVCMapID[svc.FE.ID]
	if ok {
		// If service already existed, remove old entry from map
		delete(lb.SVCMap, oldSvc.Sha256)
	}
	lb.SVCMap[svc.Sha256] = svc
	lb.SVCMapID[svc.FE.ID] = &svc
	return !ok
}

func (lb *LoadBalancer) DeleteService(svc *LBSVC) {
	delete(lb.SVCMap, svc.Sha256)
	delete(lb.SVCMapID, svc.FE.ID)
}

func NewL4Type(name string) (L4Type, error) {
	switch strings.ToLower(name) {
	case "tcp":
		return TCP, nil
	case "udp":
		return UDP, nil
	default:
		return "", fmt.Errorf("Unknown L4 protocol")
	}
}

// NewLoadBalancer returns a LoadBalancer with all maps initialized.
func NewLoadBalancer() *LoadBalancer {
	return &LoadBalancer{
		SVCMap:       SVCMap{},
		SVCMapID:     SVCMapID{},
		RevNATMap:    RevNATMap{},
		K8sServices:  map[K8sServiceNamespace]K8sServiceList{},
		K8sEndpoints: map[K8sServiceNamespace]*K8sServiceEndpoint{},
		K8sIngress:   map[K8sServiceNamespace]*K8sServiceInfo{},
	}
}

// K8sServiceNamespace is an abstraction for the k8s service + namespace types.
type K8sServiceNamespace struct {
	Service   string
	Namespace string
}

// K8sServicePorts is the list of ports associated with a Kubernetes service
type K8sServicePorts map[FEPortName]*FEPort

// String returns a human readable string representing a list of Kubernetes service ports
func (kp K8sServicePorts) String() string {
	ports := "["
	for name, p := range kp {
		ports += fmt.Sprintf("%s=%d/%s;", name, p.Port, p.Protocol)
	}

	return ports + "]"
}

// K8sServiceInfo is an abstraction for a k8s service that is composed by the frontend IP
// address (FEIP) and the map of the frontend ports (Ports).
type K8sServiceInfo struct {
	FEIP  net.IP
	Ports K8sServicePorts
}

// String returns a human readable string representing a Kubernetes service
func (k *K8sServiceInfo) String() string {
	return fmt.Sprintf("%s:%s", k.FEIP, k.Ports.String())
}

// NewK8sServiceInfo creates a new K8sServiceInfo with the Ports map initialized.
func NewK8sServiceInfo(ip net.IP) *K8sServiceInfo {
	return &K8sServiceInfo{
		FEIP:  ip,
		Ports: map[FEPortName]*FEPort{},
	}
}

// K8sServiceEndpoint is an abstraction for the k8s endpoint object. Each service is
// composed by a map of backend IPs (BEIPs) and a map of Ports (Ports). Each k8s endpoint
// present in BEIPs share the same list of Ports open.
type K8sServiceEndpoint struct {
	// TODO: Replace bool for time.Time so we know last time the service endpoint was seen?
	BEIPs map[string]bool
	Ports map[FEPortName]*L4Addr
}

// NewK8sServiceEndpoint creates a new K8sServiceEndpoint with the backend BEIPs map and
// Ports map initialized.
func NewK8sServiceEndpoint() *K8sServiceEndpoint {
	return &K8sServiceEndpoint{
		BEIPs: map[string]bool{},
		Ports: map[FEPortName]*L4Addr{},
	}
}

// L4Addr is an abstraction for the backend port with a L4Type, usually tcp or udp, and
// the Port number.
type L4Addr struct {
	Protocol L4Type
	Port     uint16
}

// NewL4Addr creates a new L4Addr. Returns an error if protocol is not recognized.
func NewL4Addr(protocol L4Type, number uint16) (*L4Addr, error) {
	switch protocol {
	case TCP, UDP, NONE:
	default:
		return nil, fmt.Errorf("unknown protocol type %s", protocol)
	}
	return &L4Addr{Protocol: protocol, Port: number}, nil
}

// DeepCopy returns a DeepCopy of the given L4Addr.
func (l *L4Addr) DeepCopy() *L4Addr {
	return &L4Addr{
		Port:     l.Port,
		Protocol: l.Protocol,
	}
}

// FEPort represents a frontend port with its ID and the L4Addr's inheritance.
type FEPort struct {
	*L4Addr
	ID ServiceID
}

// NewFEPort creates a new FEPort with the ID set to 0.
func NewFEPort(protocol L4Type, portNumber uint16) (*FEPort, error) {
	lbport, err := NewL4Addr(protocol, portNumber)
	return &FEPort{L4Addr: lbport}, err
}

// L3n4Addr is used to store, as an unique L3+L4 address in the KVStore.
type L3n4Addr struct {
	IP net.IP
	L4Addr
}

// NewL3n4Addr creates a new L3n4Addr.
func NewL3n4Addr(protocol L4Type, ip net.IP, portNumber uint16) (*L3n4Addr, error) {
	lbport, err := NewL4Addr(protocol, portNumber)
	if err != nil {
		return nil, err
	}
	return &L3n4Addr{IP: ip, L4Addr: *lbport}, nil
}

func NewL3n4AddrFromModel(base *models.FrontendAddress) (*L3n4Addr, error) {
	if base == nil {
		return nil, nil
	}

	if base.IP == "" {
		return nil, fmt.Errorf("Missing IP address")
	}

	proto, err := NewL4Type(base.Protocol)
	if err != nil {
		return nil, err
	}

	l4addr, err := NewL4Addr(proto, base.Port)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(base.IP)
	if ip == nil {
		return nil, fmt.Errorf("Invalid IP address \"%s\"", base.IP)
	}

	return &L3n4Addr{IP: ip, L4Addr: *l4addr}, nil
}

func NewLBBackEnd(protocol L4Type, ip net.IP, portNumber uint16, weight uint16) (*LBBackEnd, error) {
	lbport, err := NewL4Addr(protocol, portNumber)
	if err != nil {
		return nil, err
	}
	return &LBBackEnd{
		L3n4Addr: L3n4Addr{IP: ip, L4Addr: *lbport},
		Weight:   weight,
	}, nil
}

func NewLBBackEndFromBackendModel(base *models.BackendAddress) (*LBBackEnd, error) {
	if base.IP == nil {
		return nil, fmt.Errorf("Missing IP address")
	}

	// FIXME: Should this be NONE ?
	l4addr, err := NewL4Addr(NONE, base.Port)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(*base.IP)
	if ip == nil {
		return nil, fmt.Errorf("Invalid IP address \"%s\"", *base.IP)
	}

	return &LBBackEnd{
		L3n4Addr: L3n4Addr{IP: ip, L4Addr: *l4addr},
		Weight:   base.Weight,
	}, nil
}

func NewL3n4AddrFromBackendModel(base *models.BackendAddress) (*L3n4Addr, error) {
	if base.IP == nil {
		return nil, fmt.Errorf("Missing IP address")
	}

	// FIXME: Should this be NONE ?
	l4addr, err := NewL4Addr(NONE, base.Port)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(*base.IP)
	if ip == nil {
		return nil, fmt.Errorf("Invalid IP address \"%s\"", *base.IP)
	}
	return &L3n4Addr{IP: ip, L4Addr: *l4addr}, nil
}

func (a *L3n4Addr) GetModel() *models.FrontendAddress {
	if a == nil {
		return nil
	}

	return &models.FrontendAddress{
		IP:       a.IP.String(),
		Protocol: string(a.Protocol),
		Port:     a.Port,
	}
}

func (b *LBBackEnd) GetBackendModel() *models.BackendAddress {
	if b == nil {
		return nil
	}

	ip := b.IP.String()
	return &models.BackendAddress{
		IP:     &ip,
		Port:   b.Port,
		Weight: b.Weight,
	}
}

// String returns the L3n4Addr in the "IPv4:Port" format for IPv4 and "[IPv6]:Port" format
// for IPv6.
func (a *L3n4Addr) String() string {
	if a.IsIPv6() {
		return fmt.Sprintf("[%s]:%d", a.IP.String(), a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
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

// SHA256Sum calculates L3n4Addr's internal SHA256Sum.
func (a L3n4Addr) SHA256Sum() string {
	// FIXME: Remove Protocol's omission once we care about protocols.
	protoBak := a.Protocol
	a.Protocol = ""
	defer func() {
		a.Protocol = protoBak
	}()

	str := []byte(fmt.Sprintf("%+v", a))
	return fmt.Sprintf("%x", sha512.New512_256().Sum(str))
}

// IsIPv6 returns true if the IP address in the given L3n4Addr is IPv6 or not.
func (a *L3n4Addr) IsIPv6() bool {
	return a.IP.To4() == nil
}

// L3n4AddrID is used to store, as an unique L3+L4 plus the assigned ID, in the
// KVStore.
type L3n4AddrID struct {
	L3n4Addr
	ID ServiceID
}

// NewL3n4AddrID creates a new L3n4AddrID.
func NewL3n4AddrID(protocol L4Type, ip net.IP, portNumber uint16, id ServiceID) (*L3n4AddrID, error) {
	l3n4Addr, err := NewL3n4Addr(protocol, ip, portNumber)
	if err != nil {
		return nil, err
	}
	return &L3n4AddrID{L3n4Addr: *l3n4Addr, ID: id}, nil
}

// DeepCopy returns a DeepCopy of the given L3n4AddrID.
func (l *L3n4AddrID) DeepCopy() *L3n4AddrID {
	return &L3n4AddrID{
		L3n4Addr: *l.L3n4Addr.DeepCopy(),
		ID:       l.ID,
	}

}

// IsIPv6 returns true if the IP address in L3n4Addr's L3n4AddrID is IPv6 or not.
func (l *L3n4AddrID) IsIPv6() bool {
	return l.L3n4Addr.IsIPv6()
}

// AddFEnBE adds the given 'fe' and 'be' to the SVCMap. If 'fe' exists and beIndex is 0,
// the new 'be' will be appended to the list of existing backends. If beIndex is bigger
// than the size of existing backends slice, it will be created a new array with size of
// beIndex and the new 'be' will be inserted on index beIndex-1 of that new array. All
// remaining be elements will be kept on the same index and, in case the new array is
// larger than the number of backends, some elements will be empty.
func (svcs SVCMap) AddFEnBE(fe *L3n4AddrID, be *LBBackEnd, beIndex int) {
	sha := fe.SHA256Sum()

	var lbsvc LBSVC
	lbsvc, ok := svcs[sha]
	if !ok {
		var bes []LBBackEnd
		if beIndex == 0 {
			bes = make([]LBBackEnd, 1)
			bes[0] = *be
		} else {
			bes = make([]LBBackEnd, beIndex)
			bes[beIndex-1] = *be
		}
		lbsvc = LBSVC{
			FE:  *fe,
			BES: bes,
		}
	} else {
		var bes []LBBackEnd
		if len(lbsvc.BES) < beIndex {
			bes = make([]LBBackEnd, beIndex)
			for i, lbsvcBE := range lbsvc.BES {
				bes[i] = lbsvcBE
			}
			lbsvc.BES = bes
		}
		if beIndex == 0 {
			lbsvc.BES = append(lbsvc.BES, *be)
		} else {
			lbsvc.BES[beIndex-1] = *be
		}
	}

	svcs[sha] = lbsvc
}

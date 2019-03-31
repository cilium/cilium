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
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "loadbalancer")

	updateMetric = metrics.ServicesCount.WithLabelValues("update")
	deleteMetric = metrics.ServicesCount.WithLabelValues("delete")
	addMetric    = metrics.ServicesCount.WithLabelValues("add")
)

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

// LBBackEnd represents load balancer backend.
type LBBackEnd struct {
	ID BackendID
	L3n4Addr
	Weight uint16
}

func (lbbe *LBBackEnd) String() string {
	return fmt.Sprintf("%s, weight: %d", lbbe.L3n4Addr.String(), lbbe.Weight)
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
	spec := &models.ServiceSpec{
		ID:               id,
		FrontendAddress:  s.FE.GetModel(),
		BackendAddresses: make([]*models.BackendAddress, len(s.BES)),
	}

	for i, be := range s.BES {
		spec.BackendAddresses[i] = be.GetBackendModel()
	}

	return &models.Service{
		Spec: spec,
		Status: &models.ServiceStatus{
			Realized: spec,
		},
	}
}

// SVCMap is a map of the daemon's services. The key is the sha256sum of the LBSVC's FE
// and the value the LBSVC.
type SVCMap map[string]LBSVC

// SVCMapID maps service IDs to service structures.
type SVCMapID map[ServiceID]*LBSVC

// RevNATMap is a map of the daemon's RevNATs.
type RevNATMap map[ServiceID]L3n4Addr

// LoadBalancer is the internal representation of the loadbalancer in the local cilium
// daemon.
type LoadBalancer struct {
	BPFMapMU  lock.RWMutex
	SVCMap    SVCMap
	SVCMapID  SVCMapID
	RevNATMap RevNATMap
}

// AddService adds a service to list of loadbalancers and returns true if created.
func (lb *LoadBalancer) AddService(svc LBSVC) bool {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.ServiceName: svc.FE.String(),
		logfields.SHA:         svc.Sha256,
	})

	oldSvc, ok := lb.SVCMapID[svc.FE.ID]
	if ok {
		// If service already existed, remove old entry from Cilium's map
		scopedLog.Debug("service is already in lb.SVCMapID; deleting old entry and updating it with new entry")
		delete(lb.SVCMap, oldSvc.Sha256)
		updateMetric.Inc()
	} else {
		addMetric.Inc()
	}
	scopedLog.Debug("adding service to loadbalancer")
	lb.SVCMap[svc.Sha256] = svc
	lb.SVCMapID[svc.FE.ID] = &svc
	return !ok
}

// DeleteService deletes svc from lb's SVCMap and SVCMapID.
func (lb *LoadBalancer) DeleteService(svc *LBSVC) {
	log.WithFields(logrus.Fields{
		logfields.ServiceName: svc.FE.String(),
		logfields.SHA:         svc.Sha256,
	}).Debug("deleting service from loadbalancer")
	delete(lb.SVCMap, svc.Sha256)
	delete(lb.SVCMapID, svc.FE.ID)
	deleteMetric.Inc()
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
		SVCMap:    SVCMap{},
		SVCMapID:  SVCMapID{},
		RevNATMap: RevNATMap{},
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

// FEPort represents a frontend port with its ID and the L4Addr's inheritance.
type FEPort struct {
	*L4Addr
	ID ServiceID
}

// NewFEPort creates a new FEPort with the ID set to 0.
func NewFEPort(protocol L4Type, portNumber uint16) *FEPort {
	return &FEPort{L4Addr: NewL4Addr(protocol, portNumber)}
}

// EqualsIgnoreID returns true if both L4Addr are considered equal without
// comparing its ID.
func (f *FEPort) EqualsIgnoreID(o *FEPort) bool {
	switch {
	case (f == nil) != (o == nil):
		return false
	case (f == nil) && (o == nil):
		return true
	}
	return f.L4Addr.Equals(o.L4Addr)
}

// Equals returns true if both L4Addr are considered equal.
func (f *FEPort) Equals(o *FEPort) bool {
	switch {
	case (f == nil) != (o == nil):
		return false
	case (f == nil) && (o == nil):
		return true
	}
	return f.EqualsIgnoreID(o) && f.ID == o.ID
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
		return nil, fmt.Errorf("Missing IP address")
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
		return nil, fmt.Errorf("Invalid IP address \"%s\"", base.IP)
	}

	return &L3n4Addr{IP: ip, L4Addr: *l4addr}, nil
}

// NewLBBackEnd creates the LBBackEnd struct instance from given params.
func NewLBBackEnd(id uint16, protocol L4Type, ip net.IP, portNumber uint16, weight uint16) *LBBackEnd {
	lbport := NewL4Addr(protocol, portNumber)
	lbbe := LBBackEnd{
		ID:       BackendID(id),
		L3n4Addr: L3n4Addr{IP: ip, L4Addr: *lbport},
		Weight:   weight,
	}
	log.WithField("backend", lbbe).Debug("created new LBBackend")

	return &lbbe
}

func NewLBBackEndFromBackendModel(base *models.BackendAddress) (*LBBackEnd, error) {
	if base.IP == nil {
		return nil, fmt.Errorf("Missing IP address")
	}

	// FIXME: Should this be NONE ?
	l4addr := NewL4Addr(NONE, base.Port)
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
	l4addr := NewL4Addr(NONE, base.Port)
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
		IP:   a.IP.String(),
		Port: a.Port,
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

// SHA256Sum calculates L3n4Addr's internal SHA256Sum.
func (a L3n4Addr) SHA256Sum() string {
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
	ID ServiceID
}

// NewL3n4AddrID creates a new L3n4AddrID.
func NewL3n4AddrID(protocol L4Type, ip net.IP, portNumber uint16, id ServiceID) *L3n4AddrID {
	l3n4Addr := NewL3n4Addr(protocol, ip, portNumber)
	return &L3n4AddrID{L3n4Addr: *l3n4Addr, ID: id}
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
func (svcs SVCMap) AddFEnBE(fe *L3n4AddrID, be *LBBackEnd, beIndex int) *LBSVC {
	log.WithFields(logrus.Fields{
		"frontend":     fe,
		"backend":      be,
		"backendIndex": beIndex,
	}).Debug("adding frontend and backend to SVCMap")
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

	lbsvc.Sha256 = sha
	svcs[sha] = lbsvc
	return &lbsvc
}

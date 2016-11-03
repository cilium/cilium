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
package types

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"net"
	"sync"
)

const (
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

// LBSVC is essentially used for the REST API.
type LBSVC struct {
	FE  L3n4AddrID
	BES []L3n4Addr
}

// LoadBalancer is the internal representation of the loadbalancer in the local cilium
// daemon.
type LoadBalancer struct {
	BPFMapMU  sync.RWMutex
	SVCMap    map[string]LBSVC
	RevNATMap map[ServiceID]L3n4Addr

	K8sMU        sync.Mutex
	K8sServices  map[K8sServiceNamespace]*K8sServiceInfo
	K8sEndpoints map[K8sServiceNamespace]*K8sServiceEndpoint
}

// NewLoadBalancer returns a LoadBalancer with all maps initialized.
func NewLoadBalancer() *LoadBalancer {
	return &LoadBalancer{
		SVCMap:       map[string]LBSVC{},
		RevNATMap:    map[ServiceID]L3n4Addr{},
		K8sServices:  map[K8sServiceNamespace]*K8sServiceInfo{},
		K8sEndpoints: map[K8sServiceNamespace]*K8sServiceEndpoint{},
	}
}

// K8sServiceNamespace is an abstraction for the k8s service + namespace types.
type K8sServiceNamespace struct {
	Service   string
	Namespace string
}

// K8sServiceInfo is an abstraction for a k8s service that is composed by the frontend IP
// address (FEIP) and the map of the frontend ports (Ports).
type K8sServiceInfo struct {
	FEIP  net.IP
	Ports map[FEPortName]*FEPort
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
	case TCP, UDP:
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

// DeepCopy returns a DeepCopy of the given L3n4Addr.
func (l *L3n4Addr) DeepCopy() *L3n4Addr {
	copyIP := make(net.IP, len(l.IP))
	copy(copyIP, l.IP)
	return &L3n4Addr{
		IP:     copyIP,
		L4Addr: *l.L4Addr.DeepCopy(),
	}
}

// SHA256Sum calculates L3n4Addr's internal SHA256Sum.
func (l3n4Addr L3n4Addr) SHA256Sum() (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(l3n4Addr); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

// IsIPv6 returns true if the IP address in the given L3n4Addr is IPv6 or not.
func (l *L3n4Addr) IsIPv6() bool {
	return l.IP.To4() == nil
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

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
	TCP = L4Type("TCP")
	UDP = L4Type("UDP")
)

type L4Type string

type LBPortName string

type ServiceID uint16

type LoadBalancer struct {
	ServicesMU sync.RWMutex
	Services   map[ServiceNamespace]*ServiceInfo
	Endpoints  map[ServiceNamespace]*ServiceEndpoint
}

type ServiceNamespace struct {
	Service   string
	Namespace string
}

type ServiceInfo struct {
	IP    net.IP
	Ports map[LBPortName]*LBSvcPort
}

func (si *ServiceInfo) Equals(other *ServiceInfo) bool {
	if !si.IP.Equal(other.IP) || len(si.Ports) != len(other.Ports) {
		log.Debugf("IP different or length of ports different")
		return false
	}
	for portName, svcPort := range si.Ports {
		if otherPort, ok := other.Ports[portName]; !ok {
			log.Debugf("other doesn't have portname %+v", portName)
			return false
		} else {
			if svcPort != nil && otherPort != nil {
				// We ignore the service ID
				if !svcPort.LBPort.Equals(otherPort.LBPort) {
					log.Debugf("One of the ports is different that the other port %+v, %+v", *svcPort, *otherPort)
					return false
				}
			} else if !(svcPort == nil && otherPort == nil) {
				log.Debugf("One is nil and the other is not nil %+v, %+v", svcPort, otherPort)
				return false
			}
		}
	}
	log.Debugf("Both equals")
	return true
}

func NewServiceInfo(ip net.IP) *ServiceInfo {
	return &ServiceInfo{
		IP:    ip,
		Ports: map[LBPortName]*LBSvcPort{},
	}
}

type ServiceEndpoint struct {
	// TODO: Replace bool for time.Time so we know last time the service endpoint was seen?
	IPs   map[string]bool
	Ports map[LBPortName]*LBPort
}

func (se *ServiceEndpoint) Equals(other *ServiceEndpoint) bool {
	if se != nil && other != nil {
		if len(se.IPs) != len(other.IPs) {
			return false
		}
		if len(se.Ports) != len(other.Ports) {
			return false
		}
		for k, v := range se.IPs {
			if otherValue, ok := other.IPs[k]; !ok {
				return false
			} else {
				if v != otherValue {
					return false
				}
			}
		}
		for k, v := range se.Ports {
			if otherValue, ok := other.Ports[k]; !ok {
				return false
			} else {
				if !v.Equals(otherValue) {
					return false
				}
			}
		}
	} else if !(se == nil && other == nil) {
		return false
	}
	return true
}

func NewServiceEndpoint() *ServiceEndpoint {
	return &ServiceEndpoint{
		IPs:   map[string]bool{},
		Ports: map[LBPortName]*LBPort{},
	}
}

type LBPort struct {
	Protocol L4Type
	Port     uint16
}

func (lbp *LBPort) Equals(other *LBPort) bool {
	if lbp != nil && other != nil {
		return lbp.Protocol == other.Protocol &&
			lbp.Port == other.Port
	} else if !(lbp == nil && other == nil) {
		return false
	}
	return true
}

func NewLBPort(protocol L4Type, number uint16) (*LBPort, error) {
	switch protocol {
	case TCP, UDP:
	default:
		return nil, fmt.Errorf("unknown protocol type %s", protocol)
	}
	return &LBPort{Protocol: protocol, Port: number}, nil
}

type LBSvcPort struct {
	*LBPort
	ServiceID ServiceID
}

func NewLBSvcPort(protocol L4Type, number uint16) (*LBSvcPort, error) {
	lbport, err := NewLBPort(protocol, number)
	return &LBSvcPort{LBPort: lbport}, err
}

type ServiceL4 struct {
	IP   net.IP
	Port uint16
}

type ServiceL4ID struct {
	ServiceL4
	ServiceID
}

// SHA256Sum calculates ServiceL4's internal SHA256Sum.
func (sl4 ServiceL4) SHA256Sum() (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(sl4); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

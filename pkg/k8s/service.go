// Copyright 2018 Authors of Cilium
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

package k8s

import (
	"fmt"
	"net"
	"strings"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/service"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
)

func getAnnotationIncludeExternal(svc *v1.Service) bool {
	if value, ok := svc.ObjectMeta.Annotations[annotation.GlobalService]; ok {
		return strings.ToLower(value) == "true"
	}

	return false
}

func getAnnotationShared(svc *v1.Service) bool {
	if value, ok := svc.ObjectMeta.Annotations[annotation.SharedService]; ok {
		return strings.ToLower(value) == "true"
	}

	return getAnnotationIncludeExternal(svc)
}

// ParseServiceID parses a Kubernetes service and returns the ServiceID
func ParseServiceID(svc *v1.Service) ServiceID {
	return ServiceID{
		Name:      svc.ObjectMeta.Name,
		Namespace: svc.ObjectMeta.Namespace,
	}
}

// ParseService parses a Kubernetes service and returns a Service
func ParseService(svc *v1.Service) (ServiceID, *Service) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:    svc.ObjectMeta.Name,
		logfields.K8sNamespace:  svc.ObjectMeta.Namespace,
		logfields.K8sAPIVersion: svc.TypeMeta.APIVersion,
		logfields.K8sSvcType:    svc.Spec.Type,
	})

	svcID := ParseServiceID(svc)

	switch svc.Spec.Type {
	case v1.ServiceTypeClusterIP, v1.ServiceTypeNodePort, v1.ServiceTypeLoadBalancer:
		break

	case v1.ServiceTypeExternalName:
		// External-name services must be ignored
		return svcID, nil

	default:
		scopedLog.Warn("Ignoring k8s service: unsupported type")
		return svcID, nil
	}

	if svc.Spec.ClusterIP == "" {
		scopedLog.Info("Ignoring k8s service: empty ClusterIP")
		return svcID, nil
	}

	clusterIP := net.ParseIP(svc.Spec.ClusterIP)
	headless := false
	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		headless = true
	}
	svcInfo := NewService(clusterIP, headless, svc.Labels, svc.Spec.Selector)
	svcInfo.IncludeExternal = getAnnotationIncludeExternal(svc)
	svcInfo.Shared = getAnnotationShared(svc)

	// FIXME: Add support for
	//  - NodePort
	for _, port := range svc.Spec.Ports {
		p := loadbalancer.NewFEPort(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
		if _, ok := svcInfo.Ports[loadbalancer.FEPortName(port.Name)]; !ok {
			svcInfo.Ports[loadbalancer.FEPortName(port.Name)] = p
		}
	}

	return svcID, svcInfo
}

// ServiceID identities the Kubernetes service
type ServiceID struct {
	Name      string `json:"serviceName,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// String returns the string representation of a service ID
func (s ServiceID) String() string {
	return fmt.Sprintf("%s/%s", s.Namespace, s.Name)
}

// Service is an abstraction for a k8s service that is composed by the frontend IP
// address (FEIP) and the map of the frontend ports (Ports).
type Service struct {
	FrontendIP net.IP
	IsHeadless bool

	// IncludeExternal is true when external endpoints from other clusters
	// should be included
	IncludeExternal bool

	// Shared is true when the service should be exposed/shared to other clusters
	Shared bool

	Ports    map[loadbalancer.FEPortName]*loadbalancer.FEPort
	Labels   map[string]string
	Selector map[string]string
}

// String returns the string representation of a service resource
func (s *Service) String() string {
	if s == nil {
		return "nil"
	}

	ports := make([]string, len(s.Ports))
	i := 0
	for p := range s.Ports {
		ports[i] = string(p)
		i++
	}

	return fmt.Sprintf("frontend:%s/ports=%s/selector=%v", s.FrontendIP.String(), ports, s.Selector)
}

// IsExternal returns true if the service is expected to serve out-of-cluster endpoints:
func (s Service) IsExternal() bool {
	return len(s.Selector) == 0
}

// DeepEquals returns true if both services are equal
func (s *Service) DeepEquals(o *Service) bool {
	switch {
	case (s == nil) != (o == nil):
		return false
	case (s == nil) && (o == nil):
		return true
	}
	if s.IsHeadless == o.IsHeadless &&
		s.FrontendIP.Equal(o.FrontendIP) &&
		comparator.MapStringEquals(s.Labels, o.Labels) &&
		comparator.MapStringEquals(s.Selector, o.Selector) {

		if ((s.Ports == nil) != (o.Ports == nil)) ||
			len(s.Ports) != len(o.Ports) {
			return false
		}
		for portName, port := range s.Ports {
			oPort, ok := o.Ports[portName]
			if !ok {
				return false
			}
			if !port.EqualsIgnoreID(oPort) {
				return false
			}
		}
		return true
	}
	return false
}

// NewService returns a new Service with the Ports map initialized.
func NewService(ip net.IP, headless bool, labels map[string]string, selector map[string]string) *Service {
	return &Service{
		FrontendIP: ip,
		IsHeadless: headless,
		Ports:      map[loadbalancer.FEPortName]*loadbalancer.FEPort{},
		Labels:     labels,
		Selector:   selector,
	}
}

// UniquePorts returns a map of all unique ports configured in the service
func (s *Service) UniquePorts() map[uint16]bool {
	// We are not discriminating the different L4 protocols on the same L4
	// port so we create the number of unique sets of service IP + service
	// port.
	uniqPorts := map[uint16]bool{}
	for _, p := range s.Ports {
		uniqPorts[p.Port] = true
	}
	return uniqPorts
}

// NewClusterService returns the service.ClusterService representing a
// Kubernetes Service
func NewClusterService(id ServiceID, k8sService *Service, k8sEndpoints *Endpoints) service.ClusterService {
	svc := service.NewClusterService(id.Name, id.Namespace)

	for key, value := range k8sService.Labels {
		svc.Labels[key] = value
	}

	for key, value := range k8sService.Selector {
		svc.Selector[key] = value
	}

	portConfig := service.PortConfiguration{}
	for portName, port := range k8sService.Ports {
		portConfig[string(portName)] = port.L4Addr
	}

	svc.Frontends = map[string]service.PortConfiguration{}
	svc.Frontends[k8sService.FrontendIP.String()] = portConfig

	svc.Backends = map[string]service.PortConfiguration{}
	for ipString, portConfig := range k8sEndpoints.Backends {
		svc.Backends[ipString] = portConfig
	}

	return svc
}

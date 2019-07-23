// Copyright 2018-2019 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
)

func getAnnotationIncludeExternal(svc *types.Service) bool {
	if value, ok := svc.ObjectMeta.Annotations[annotation.GlobalService]; ok {
		return strings.ToLower(value) == "true"
	}

	return false
}

func getAnnotationShared(svc *types.Service) bool {
	if value, ok := svc.ObjectMeta.Annotations[annotation.SharedService]; ok {
		return strings.ToLower(value) == "true"
	}

	return getAnnotationIncludeExternal(svc)
}

// ParseServiceID parses a Kubernetes service and returns the ServiceID
func ParseServiceID(svc *types.Service) ServiceID {
	return ServiceID{
		Name:        svc.ObjectMeta.Name,
		Namespace:   svc.ObjectMeta.Namespace,
		k8sExternal: len(svc.Spec.ExternalIPs) != 0,
	}
}

// ParseService parses a Kubernetes service and returns a Service
func ParseService(svc *types.Service) (ServiceID, *Service) {
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

	if len(svc.Spec.ExternalIPs) != 0 {
		// Accordingly with k8s docs: Traffic that ingresses into the cluster
		// with the external IP (as destination IP), on the service port, will
		// be routed to one of the service endpoints.
		// For Cilium this means the backends are the cartesian product of
		// service ports x external IPs + real k8s endpoints and the service IP
		// will continue to be the service IP.
		eps := newEndpoints()
		for _, ipStr := range svc.Spec.ExternalIPs {
			portCfg := service.PortConfiguration{}
			for _, port := range svc.Spec.Ports {
				portCfg[port.Name] = loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
			}
			eps.Backends[ipStr] = portCfg
		}
		svcInfo.K8sExternalIPs = eps
	}

	for _, port := range svc.Spec.Ports {
		p := loadbalancer.NewFEPort(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
		portName := loadbalancer.FEPortName(port.Name)
		if _, ok := svcInfo.Ports[portName]; !ok {
			svcInfo.Ports[portName] = p
		}
		// This is a hack;-( In the case of NodePort service, we need to create
		// three surrogate frontends per IP protocol - one with a zero IP addr used
		// by the host-lb, one with a public iface IP addr and one with cilium_host
		// IP addr.
		// For each frontend we will need to store a service ID used for a reverse
		// NAT translation and for deleting a service.
		// Unfortunately, doing this in daemon/{loadbalancer,k8s_watcher}.go
		// would introduce more complexity in already too complex LB codebase,
		// so for now (until we have refactored the LB code) keep NodePort
		// frontends in Service.NodePorts.
		if svc.Spec.Type == v1.ServiceTypeNodePort {
			if option.Config.EnableNodePort {
				if _, ok := svcInfo.NodePorts[portName]; !ok {
					svcInfo.NodePorts[portName] =
						make(map[string]*loadbalancer.L3n4AddrID)
				}
				proto := loadbalancer.L4Type(port.Protocol)
				port := uint16(port.NodePort)
				id := loadbalancer.ID(0) // will be allocated by k8s_watcher

				// TODO(brb) switch to if-clause when dual stack is supported
				switch {
				case option.Config.EnableIPv4 &&
					clusterIP != nil && !strings.Contains(svc.Spec.ClusterIP, ":"):

					for _, ip := range []net.IP{net.IPv4(0, 0, 0, 0), node.GetNodePortIPv4(), node.GetInternalIPv4()} {
						nodePortFE := loadbalancer.NewL3n4AddrID(proto, ip, port, id)
						svcInfo.NodePorts[portName][nodePortFE.String()] = nodePortFE

					}
				case option.Config.EnableIPv6 &&
					clusterIP != nil && strings.Contains(svc.Spec.ClusterIP, ":"):

					for _, ip := range []net.IP{net.IPv6zero, node.GetNodePortIPv6(), node.GetIPv6()} {
						nodePortFE := loadbalancer.NewL3n4AddrID(proto, ip, port, id)
						svcInfo.NodePorts[portName][nodePortFE.String()] = nodePortFE
					}
				}
			}
		}
	}

	return svcID, svcInfo
}

// ServiceID identities the Kubernetes service
type ServiceID struct {
	Name      string `json:"serviceName,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	// k8sExternal accounts if the service contains external K8s IPs or not.
	k8sExternal bool
}

// String returns the string representation of a service ID
func (s ServiceID) String() string {
	return fmt.Sprintf("%s/%s", s.Namespace, s.Name)
}

// ParseServiceIDFrom returns a ServiceID derived from the given kubernetes
// service FQDN.
func ParseServiceIDFrom(dn string) *ServiceID {
	// typical service name "cilium-etcd-client.kube-system.svc"
	idx1 := strings.IndexByte(dn, '.')
	if idx1 >= 0 {
		svc := ServiceID{
			Name: dn[:idx1],
		}
		idx2 := strings.IndexByte(dn[idx1+1:], '.')
		if idx2 >= 0 {
			// "cilium-etcd-client.kube-system.svc"
			//                     ^idx1+1    ^ idx1+1+idx2
			svc.Namespace = dn[idx1+1 : idx1+1+idx2]
		} else {
			// "cilium-etcd-client.kube-system"
			//                     ^idx1+1
			svc.Namespace = dn[idx1+1:]
		}
		return &svc
	}
	return nil
}

// Service is an abstraction for a k8s service that is composed by the frontend IP
// address (FEIP) and the map of the frontend ports (Ports).
type Service struct {
	FrontendIP net.IP
	IsHeadless bool

	// K8sExternalIPs contains the list of external endpoints if the service has
	// external IPs defined.
	K8sExternalIPs *Endpoints

	// IncludeExternal is true when external endpoints from other clusters
	// should be included
	IncludeExternal bool

	// Shared is true when the service should be exposed/shared to other clusters
	Shared bool

	Ports map[loadbalancer.FEPortName]*loadbalancer.FEPort
	// NodePorts stores mapping for port name => NodePort frontend addr string =>
	// NodePort fronted addr. The string addr => addr indirection is to avoid
	// storing duplicates.
	NodePorts map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID
	Labels    map[string]string
	Selector  map[string]string
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

// IsK8sExternal returns true if the service is expected to serve out-of-cluster IP addresses
func (s *Service) IsK8sExternal() bool {
	return s.K8sExternalIPs != nil
}

// DeepEquals returns true if both services are equal
func (s *Service) DeepEquals(o *Service) bool {
	switch {
	case (s == nil) != (o == nil):
		return false
	case (s == nil) && (o == nil):
		return true
	}

	if !s.K8sExternalIPs.DeepEquals(o.K8sExternalIPs) {
		return false
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

		if ((s.NodePorts == nil) != (o.NodePorts == nil)) ||
			len(s.NodePorts) != len(o.NodePorts) {
			return false
		}
		for portName, nodePorts := range s.NodePorts {
			oNodePorts, ok := o.NodePorts[portName]
			if !ok {
				return false
			}
			if ((nodePorts == nil) != (oNodePorts == nil)) ||
				len(nodePorts) != len(oNodePorts) {
				return false
			}
			for nodePortName, nodePort := range nodePorts {
				oNodePort, ok := oNodePorts[nodePortName]
				if !ok {
					return false
				}
				if !nodePort.Equals(oNodePort) {
					return false
				}
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
		NodePorts:  map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID{},
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

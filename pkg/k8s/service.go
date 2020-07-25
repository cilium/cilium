// Copyright 2018-2020 Authors of Cilium
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
	"net/url"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/datapath"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	serviceStore "github.com/cilium/cilium/pkg/service/store"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

func getAnnotationIncludeExternal(svc *slim_corev1.Service) bool {
	if value, ok := svc.ObjectMeta.Annotations[annotation.GlobalService]; ok {
		return strings.ToLower(value) == "true"
	}

	return false
}

func getAnnotationShared(svc *slim_corev1.Service) bool {
	if value, ok := svc.ObjectMeta.Annotations[annotation.SharedService]; ok {
		return strings.ToLower(value) == "true"
	}

	return getAnnotationIncludeExternal(svc)
}

// ParseServiceID parses a Kubernetes service and returns the ServiceID
func ParseServiceID(svc *slim_corev1.Service) ServiceID {
	return ServiceID{
		Name:      svc.ObjectMeta.Name,
		Namespace: svc.ObjectMeta.Namespace,
	}
}

// ParseService parses a Kubernetes service and returns a Service
func ParseService(svc *slim_corev1.Service, nodeAddressing datapath.NodeAddressing) (ServiceID, *Service) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:    svc.ObjectMeta.Name,
		logfields.K8sNamespace:  svc.ObjectMeta.Namespace,
		logfields.K8sAPIVersion: svc.TypeMeta.APIVersion,
		logfields.K8sSvcType:    svc.Spec.Type,
	})
	var loadBalancerIPs []string

	svcID := ParseServiceID(svc)

	switch svc.Spec.Type {
	case slim_corev1.ServiceTypeClusterIP, slim_corev1.ServiceTypeNodePort, slim_corev1.ServiceTypeLoadBalancer:
		break

	case slim_corev1.ServiceTypeExternalName:
		// External-name services must be ignored
		return ServiceID{}, nil

	default:
		scopedLog.Warn("Ignoring k8s service: unsupported type")
		return ServiceID{}, nil
	}

	if svc.Spec.ClusterIP == "" && (!option.Config.EnableNodePort || len(svc.Spec.ExternalIPs) == 0) {
		return ServiceID{}, nil
	}

	clusterIP := net.ParseIP(svc.Spec.ClusterIP)
	headless := false
	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		headless = true
	}

	var trafficPolicy loadbalancer.SVCTrafficPolicy
	switch svc.Spec.ExternalTrafficPolicy {
	case slim_corev1.ServiceExternalTrafficPolicyTypeLocal:
		trafficPolicy = loadbalancer.SVCTrafficPolicyLocal
	default:
		trafficPolicy = loadbalancer.SVCTrafficPolicyCluster
	}

	for _, ip := range svc.Status.LoadBalancer.Ingress {
		if ip.IP != "" {
			loadBalancerIPs = append(loadBalancerIPs, ip.IP)
		}
	}

	svcInfo := NewService(clusterIP, svc.Spec.ExternalIPs,
		loadBalancerIPs, svc.Spec.LoadBalancerSourceRanges, headless,
		trafficPolicy, uint16(svc.Spec.HealthCheckNodePort), svc.Labels, svc.Spec.Selector)
	svcInfo.IncludeExternal = getAnnotationIncludeExternal(svc)
	svcInfo.Shared = getAnnotationShared(svc)

	if svc.Spec.SessionAffinity == slim_corev1.ServiceAffinityClientIP {
		svcInfo.SessionAffinity = true
		if cfg := svc.Spec.SessionAffinityConfig; cfg != nil && cfg.ClientIP != nil && cfg.ClientIP.TimeoutSeconds != nil {
			svcInfo.SessionAffinityTimeoutSec = uint32(*cfg.ClientIP.TimeoutSeconds)
		}
		if svcInfo.SessionAffinityTimeoutSec == 0 {
			svcInfo.SessionAffinityTimeoutSec = uint32(v1.DefaultClientIPServiceAffinitySeconds)
		}
	}

	for _, port := range svc.Spec.Ports {
		p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
		portName := loadbalancer.FEPortName(port.Name)
		if _, ok := svcInfo.Ports[portName]; !ok {
			svcInfo.Ports[portName] = p
		}
		// TODO(brb) Get rid of this hack by moving the creation of surrogate
		// frontends to pkg/service.
		//
		// This is a hack;-( In the case of NodePort service, we need to create
		// surrogate frontends per IP protocol - one with a zero IP addr and
		// one per each public iface IP addr.
		if svc.Spec.Type == slim_corev1.ServiceTypeNodePort || svc.Spec.Type == slim_corev1.ServiceTypeLoadBalancer {
			if option.Config.EnableNodePort && nodeAddressing != nil {
				if _, ok := svcInfo.NodePorts[portName]; !ok {
					svcInfo.NodePorts[portName] =
						make(map[string]*loadbalancer.L3n4AddrID)
				}
				proto := loadbalancer.L4Type(port.Protocol)
				port := uint16(port.NodePort)
				id := loadbalancer.ID(0) // will be allocated by k8s_watcher
				if !option.Config.EnableIPv4 &&
					svc.Spec.IPFamily == slim_corev1.IPv4Protocol {
					scopedLog.Warnf(`service spec, %v, specifies an "IPFamily" of IPv4, but %q is not enabled`, svc.Spec, option.EnableIPv4Name)
				}
				if !option.Config.EnableIPv6 &&
					svc.Spec.IPFamily == slim_corev1.IPv6Protocol {
					scopedLog.Warnf(`service spec, %v, specifies an "IPFamily" of IPv6, but %q is not enabled`, svc.Spec, option.EnableIPv6Name)
				}
				if option.Config.EnableIPv4 &&
					(svc.Spec.IPFamily == slim_corev1.IPNone || svc.Spec.IPFamily == slim_corev1.IPv4Protocol) &&
					clusterIP != nil && !strings.Contains(svc.Spec.ClusterIP, ":") {

					for _, ip := range nodeAddressing.IPv4().LoadBalancerNodeAddresses() {
						nodePortFE := loadbalancer.NewL3n4AddrID(proto, ip, port,
							loadbalancer.ScopeExternal, id)
						svcInfo.NodePorts[portName][nodePortFE.String()] = nodePortFE
					}
				}
				if option.Config.EnableIPv6 &&
					(svc.Spec.IPFamily == slim_corev1.IPNone || svc.Spec.IPFamily == slim_corev1.IPv6Protocol) &&
					clusterIP != nil && strings.Contains(svc.Spec.ClusterIP, ":") {

					for _, ip := range nodeAddressing.IPv6().LoadBalancerNodeAddresses() {
						nodePortFE := loadbalancer.NewL3n4AddrID(proto, ip, port,
							loadbalancer.ScopeExternal, id)
						svcInfo.NodePorts[portName][nodePortFE.String()] = nodePortFE
					}
				}
			}
		}
	}

	return svcID, svcInfo
}

// ServiceID identifies the Kubernetes service
type ServiceID struct {
	Name      string `json:"serviceName,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// String returns the string representation of a service ID
func (s ServiceID) String() string {
	return fmt.Sprintf("%s/%s", s.Namespace, s.Name)
}

// EndpointSliceID identifies a Kubernetes EndpointSlice as well as the legacy
// v1.Endpoints.
type EndpointSliceID struct {
	ServiceID
	EndpointSliceName string
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
// +k8s:deepcopy-gen=true
type Service struct {
	FrontendIP net.IP
	IsHeadless bool

	// IncludeExternal is true when external endpoints from other clusters
	// should be included
	IncludeExternal bool

	// Shared is true when the service should be exposed/shared to other clusters
	Shared bool

	// TrafficPolicy controls how backends are selected. If set to "Local", only
	// node-local backends are chosen
	TrafficPolicy loadbalancer.SVCTrafficPolicy

	// HealthCheckNodePort defines on which port the node runs a HTTP health
	// check server which may be used by external loadbalancers to determine
	// if a node has local backends. This will only have effect if both
	// LoadBalancerIPs is not empty and TrafficPolicy is SVCTrafficPolicyLocal.
	HealthCheckNodePort uint16

	Ports map[loadbalancer.FEPortName]*loadbalancer.L4Addr
	// NodePorts stores mapping for port name => NodePort frontend addr string =>
	// NodePort fronted addr. The string addr => addr indirection is to avoid
	// storing duplicates.
	NodePorts map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID
	// K8sExternalIPs stores mapping of the endpoint in a string format to the
	// externalIP in net.IP format.
	K8sExternalIPs map[string]net.IP

	// LoadBalancerIPs stores LB IPs assigned to the service (string(IP) => IP).
	LoadBalancerIPs          map[string]net.IP
	LoadBalancerSourceRanges map[string]*cidr.CIDR

	Labels   map[string]string
	Selector map[string]string

	// SessionAffinity denotes whether service has the clientIP session affinity
	SessionAffinity bool
	// SessionAffinityTimeoutSeconds denotes session affinity timeout
	SessionAffinityTimeoutSec uint32
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
		s.TrafficPolicy == o.TrafficPolicy &&
		s.HealthCheckNodePort == o.HealthCheckNodePort &&
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
			if !port.Equals(oPort) {
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

		if ((s.K8sExternalIPs == nil) != (o.K8sExternalIPs == nil)) ||
			len(s.K8sExternalIPs) != len(o.K8sExternalIPs) {
			return false
		}
		for k, v := range s.K8sExternalIPs {
			vOther, ok := o.K8sExternalIPs[k]
			if !ok || !v.Equal(vOther) {
				return false
			}
		}

		if ((s.LoadBalancerIPs == nil) != (o.LoadBalancerIPs == nil)) ||
			len(s.LoadBalancerIPs) != len(o.LoadBalancerIPs) {
			return false
		}
		for k, v := range s.LoadBalancerIPs {
			vOther, ok := o.LoadBalancerIPs[k]
			if !ok || !v.Equal(vOther) {
				return false
			}
		}
		if ((s.LoadBalancerSourceRanges == nil) != (o.LoadBalancerSourceRanges == nil)) ||
			len(s.LoadBalancerSourceRanges) != len(o.LoadBalancerSourceRanges) {
			return false
		}
		for k, v := range s.LoadBalancerSourceRanges {
			vOther, ok := o.LoadBalancerSourceRanges[k]
			if !ok || !v.Equal(vOther) {
				return false
			}
		}
		return true
	}
	return false
}

func parseIPs(externalIPs []string) map[string]net.IP {
	m := map[string]net.IP{}
	for _, externalIP := range externalIPs {
		ip := net.ParseIP(externalIP)
		if ip != nil {
			m[externalIP] = ip
		}
	}
	return m
}

// NewService returns a new Service with the Ports map initialized.
func NewService(ip net.IP, externalIPs []string,
	loadBalancerIPs []string, loadBalancerSourceRanges []string,
	headless bool, trafficPolicy loadbalancer.SVCTrafficPolicy,
	healthCheckNodePort uint16, labels, selector map[string]string) *Service {

	var (
		k8sExternalIPs     map[string]net.IP
		k8sLoadBalancerIPs map[string]net.IP
	)

	loadBalancerSourceCIDRs := make(map[string]*cidr.CIDR, len(loadBalancerSourceRanges))

	for _, cidrString := range loadBalancerSourceRanges {
		cidr, _ := cidr.ParseCIDR(cidrString)
		loadBalancerSourceCIDRs[cidr.String()] = cidr
	}

	if option.Config.EnableNodePort {
		k8sExternalIPs = parseIPs(externalIPs)
		k8sLoadBalancerIPs = parseIPs(loadBalancerIPs)
	}

	return &Service{
		FrontendIP: ip,

		IsHeadless:          headless,
		TrafficPolicy:       trafficPolicy,
		HealthCheckNodePort: healthCheckNodePort,

		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]map[string]*loadbalancer.L3n4AddrID{},
		K8sExternalIPs:           k8sExternalIPs,
		LoadBalancerIPs:          k8sLoadBalancerIPs,
		LoadBalancerSourceRanges: loadBalancerSourceCIDRs,

		Labels:   labels,
		Selector: selector,
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

// NewClusterService returns the serviceStore.ClusterService representing a
// Kubernetes Service
func NewClusterService(id ServiceID, k8sService *Service, k8sEndpoints *Endpoints) serviceStore.ClusterService {
	svc := serviceStore.NewClusterService(id.Name, id.Namespace)

	for key, value := range k8sService.Labels {
		svc.Labels[key] = value
	}

	for key, value := range k8sService.Selector {
		svc.Selector[key] = value
	}

	portConfig := serviceStore.PortConfiguration{}
	for portName, port := range k8sService.Ports {
		portConfig[string(portName)] = port
	}

	svc.Frontends = map[string]serviceStore.PortConfiguration{}
	svc.Frontends[k8sService.FrontendIP.String()] = portConfig

	svc.Backends = map[string]serviceStore.PortConfiguration{}
	for ipString, backend := range k8sEndpoints.Backends {
		svc.Backends[ipString] = backend.Ports
	}

	return svc
}

type ServiceIPGetter interface {
	GetServiceIP(svcID ServiceID) *loadbalancer.L3n4Addr
}

// CreateCustomDialer returns a custom dialer that picks the service IP,
// from the given ServiceIPGetter, if the address the used to dial is a k8s
// service.
func CreateCustomDialer(b ServiceIPGetter, log *logrus.Entry) func(s string, duration time.Duration) (conn net.Conn, e error) {
	return func(s string, duration time.Duration) (conn net.Conn, e error) {
		// If the service is available, do the service translation to
		// the service IP. Otherwise dial with the original service
		// name `s`.
		u, err := url.Parse(s)
		if err == nil {
			svc := ParseServiceIDFrom(u.Host)
			if svc != nil {
				svcIP := b.GetServiceIP(*svc)
				if svcIP != nil {
					s = svcIP.String()
				}
			} else {
				log.Debug("Service not found")
			}
			log.Debugf("custom dialer based on k8s service backend is dialing to %q", s)
		} else {
			log.Errorf("Unable to parse etcd service URL %s", err)
		}
		return net.Dial("tcp", s)
	}
}

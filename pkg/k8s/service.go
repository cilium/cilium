// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"strings"

	v1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func getAnnotationServiceForwardingMode(cfg loadbalancer.Config, svc *slim_corev1.Service) (loadbalancer.SVCForwardingMode, error) {
	if value, ok := annotation.Get(svc, annotation.ServiceForwardingMode); ok {
		val := loadbalancer.ToSVCForwardingMode(strings.ToLower(value))
		if val != loadbalancer.SVCForwardingModeUndef {
			return val, nil
		}
		return loadbalancer.ToSVCForwardingMode(cfg.LBMode), fmt.Errorf("Value %q is not supported for %q", val, annotation.ServiceForwardingMode)
	}
	return loadbalancer.ToSVCForwardingMode(cfg.LBMode), nil
}

func getAnnotationServiceLoadBalancingAlgorithm(cfg loadbalancer.Config, svc *slim_corev1.Service) (loadbalancer.SVCLoadBalancingAlgorithm, error) {
	return GetAnnotationServiceLoadBalancingAlgorithm(svc.Annotations, loadbalancer.ToSVCLoadBalancingAlgorithm(cfg.LBAlgorithm))
}

func GetAnnotationServiceLoadBalancingAlgorithm(ann map[string]string, defaultAlg loadbalancer.SVCLoadBalancingAlgorithm) (loadbalancer.SVCLoadBalancingAlgorithm, error) {
	if value, ok := ann[annotation.ServiceLoadBalancingAlgorithm]; ok {
		val := loadbalancer.ToSVCLoadBalancingAlgorithm(strings.ToLower(value))
		if val != loadbalancer.SVCLoadBalancingAlgorithmUndef {
			return val, nil
		}
		return defaultAlg, fmt.Errorf("Value %q is not supported for %q", val, annotation.ServiceLoadBalancingAlgorithm)
	}
	return defaultAlg, nil
}

func getTopologyAware(svc *slim_corev1.Service) bool {
	return getAnnotationTopologyAwareHints(svc) ||
		(svc.Spec.TrafficDistribution != nil &&
			*svc.Spec.TrafficDistribution == v1.ServiceTrafficDistributionPreferClose)
}

func getAnnotationTopologyAwareHints(svc *slim_corev1.Service) bool {
	// v1.DeprecatedAnnotationTopologyAwareHints has precedence over v1.AnnotationTopologyMode.
	value, ok := svc.ObjectMeta.Annotations[v1.DeprecatedAnnotationTopologyAwareHints]
	if !ok {
		value = svc.ObjectMeta.Annotations[v1.AnnotationTopologyMode]
	}
	return !(value == "" || value == "disabled" || value == "Disabled")
}

func getAnnotationServiceSourceRangesPolicy(svc *slim_corev1.Service) loadbalancer.SVCSourceRangesPolicy {
	if value, ok := annotation.Get(svc, annotation.ServiceSourceRangesPolicy); ok {
		tmp := loadbalancer.SVCSourceRangesPolicy(strings.ToLower(value))
		if tmp == loadbalancer.SVCSourceRangesPolicyDeny {
			return tmp
		}
	}

	return loadbalancer.SVCSourceRangesPolicyAllow
}

func getAnnotationServiceProxyDelegation(svc *slim_corev1.Service) loadbalancer.SVCProxyDelegation {
	if value, ok := annotation.Get(svc, annotation.ServiceProxyDelegation); ok {
		tmp := loadbalancer.SVCProxyDelegation(strings.ToLower(value))
		if tmp == loadbalancer.SVCProxyDelegationDelegateIfLocal {
			return tmp
		}
	}

	return loadbalancer.SVCProxyDelegationNone
}

// isValidServiceFrontendIP returns true if the provided service frontend IP address type
// is supported in cilium configuration.
func isValidServiceFrontendIP(netIP net.IP) bool {
	if (option.Config.EnableIPv4 && ip.IsIPv4(netIP)) || (option.Config.EnableIPv6 && ip.IsIPv6(netIP)) {
		return true
	}

	return false
}

// exposeSvcType is used to determine whether a given service can be provisioned
// for a given service type (passed to the "canExpose" method).
//
// This is controlled by the ServiceTypeExposure K8s Service annotation. If it
// set, then only the service type in the value is provisioned. For example, a
// LoadBalancer service includes ClusterIP and NodePort (unless
// allocateLoadBalancerNodePorts is set to false). To avoid provisioning the
// latter two, one can set the annotation with the value "LoadBalancer".
type exposeSvcType slim_corev1.ServiceType

func NewSvcExposureType(svc *slim_corev1.Service) (*exposeSvcType, error) {
	typ, isSet := svc.Annotations[annotation.ServiceTypeExposure]
	if !isSet {
		return nil, nil
	}

	svcType := slim_corev1.ServiceType(typ)

	switch svcType {
	case slim_corev1.ServiceTypeClusterIP,
		slim_corev1.ServiceTypeNodePort,
		slim_corev1.ServiceTypeLoadBalancer:
	default:
		return nil,
			fmt.Errorf("not supported type for %q: %s", annotation.ServiceTypeExposure, typ)
	}

	expType := exposeSvcType(svcType)
	return &expType, nil
}

// CanExpose checks whether a given service type can be provisioned.
func (e *exposeSvcType) CanExpose(t slim_corev1.ServiceType) bool {
	if e == nil {
		return true
	}

	return slim_corev1.ServiceType(*e) == t
}

// ParseServiceID parses a Kubernetes service and returns the ServiceID
func ParseServiceID(svc *slim_corev1.Service) ServiceID {
	return ServiceID{
		Name:      svc.ObjectMeta.Name,
		Namespace: svc.ObjectMeta.Namespace,
	}
}

// ParseService parses a Kubernetes service and returns a Service.
func ParseService(logger *slog.Logger, cfg loadbalancer.Config, svc *slim_corev1.Service, nodePortAddrs []netip.Addr) (ServiceID, *Service) {
	scopedLog := logger.With(
		logfields.K8sSvcName, svc.ObjectMeta.Name,
		logfields.K8sNamespace, svc.ObjectMeta.Namespace,
		logfields.K8sAPIVersion, svc.TypeMeta.APIVersion,
		logfields.K8sSvcType, svc.Spec.Type,
	)
	var loadBalancerIPs []string

	svcID := ParseServiceID(svc)
	expType, err := NewSvcExposureType(svc)
	if err != nil {
		scopedLog.Warn(
			"Ignoring annotation",
			logfields.Error, err,
			logfields.Annotation, annotation.ServiceTypeExposure,
		)
	}

	var svcType loadbalancer.SVCType
	switch svc.Spec.Type {
	case slim_corev1.ServiceTypeClusterIP:
		svcType = loadbalancer.SVCTypeClusterIP

	case slim_corev1.ServiceTypeNodePort:
		svcType = loadbalancer.SVCTypeNodePort

	case slim_corev1.ServiceTypeLoadBalancer:
		svcType = loadbalancer.SVCTypeLoadBalancer

	case slim_corev1.ServiceTypeExternalName:
		// External-name services must be ignored
		return ServiceID{}, nil

	default:
		scopedLog.Warn(
			"Ignoring k8s service: unsupported type",
		)
		return ServiceID{}, nil
	}

	if svc.Spec.ClusterIP == "" && (!option.Config.EnableNodePort || len(svc.Spec.ExternalIPs) == 0) {
		return ServiceID{}, nil
	}

	var clusterIPs []net.IP
	if expType.CanExpose(slim_corev1.ServiceTypeClusterIP) {
		if len(svc.Spec.ClusterIPs) == 0 {
			if clsIP := net.ParseIP(svc.Spec.ClusterIP); clsIP != nil {
				clusterIPs = []net.IP{clsIP}
			}
		} else {
			// Here we assume that the value of .spec.ClusterIPs[0] is same as that of the .spec.clusterIP
			// or else Kubernetes will reject the service with validation error.
			for _, ip := range svc.Spec.ClusterIPs {
				if parsedIP := net.ParseIP(ip); parsedIP != nil {
					clusterIPs = append(clusterIPs, parsedIP)
				}
			}
		}
	}

	_, headless := svc.Labels[v1.IsHeadlessService]
	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		headless = true
	}

	var extTrafficPolicy loadbalancer.SVCTrafficPolicy
	switch svc.Spec.ExternalTrafficPolicy {
	case slim_corev1.ServiceExternalTrafficPolicyLocal:
		extTrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
	default:
		extTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
	}

	var intTrafficPolicy loadbalancer.SVCTrafficPolicy
	if svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == slim_corev1.ServiceInternalTrafficPolicyLocal && option.Config.EnableInternalTrafficPolicy {
		intTrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
	} else {
		intTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
	}

	if expType.CanExpose(slim_corev1.ServiceTypeLoadBalancer) {
		for _, ip := range svc.Status.LoadBalancer.Ingress {
			if ip.IP != "" && (ip.IPMode == nil || *ip.IPMode == slim_corev1.LoadBalancerIPModeVIP) {
				loadBalancerIPs = append(loadBalancerIPs, ip.IP)
			}
		}
	}
	lbSrcRanges := make([]string, 0, len(svc.Spec.LoadBalancerSourceRanges))
	for _, cidrString := range svc.Spec.LoadBalancerSourceRanges {
		cidrStringTrimmed := strings.TrimSpace(cidrString)
		lbSrcRanges = append(lbSrcRanges, cidrStringTrimmed)
	}

	svcInfo := NewService(clusterIPs, svc.Spec.ExternalIPs, loadBalancerIPs,
		lbSrcRanges, headless, extTrafficPolicy, intTrafficPolicy,
		uint16(svc.Spec.HealthCheckNodePort), svc.Annotations, svc.Labels, svc.Spec.Selector,
		svc.GetNamespace(), svcType)

	svcInfo.SourceRangesPolicy = getAnnotationServiceSourceRangesPolicy(svc)
	svcInfo.ProxyDelegation = getAnnotationServiceProxyDelegation(svc)
	svcInfo.IncludeExternal = annotation.GetAnnotationIncludeExternal(svc)
	svcInfo.ServiceAffinity = annotation.GetAnnotationServiceAffinity(svc)
	svcInfo.Shared = annotation.GetAnnotationShared(svc)

	svcInfo.ForwardingMode = loadbalancer.ToSVCForwardingMode(cfg.LBMode)
	if cfg.AlgorithmAnnotation {
		var err error

		svcInfo.ForwardingMode, err = getAnnotationServiceForwardingMode(cfg, svc)
		if err != nil {
			scopedLog.Warn(
				"Ignoring annotation, applying global configuration",
				logfields.Error, err,
				logfields.Annotation, annotation.ServiceForwardingMode,
				logfields.GlobalConfiguration, svcInfo.ForwardingMode,
			)
		}
	}

	svcInfo.LoadBalancerAlgorithm = loadbalancer.ToSVCLoadBalancingAlgorithm(cfg.LBAlgorithm)
	if cfg.AlgorithmAnnotation {
		var err error

		svcInfo.LoadBalancerAlgorithm, err = getAnnotationServiceLoadBalancingAlgorithm(cfg, svc)
		if err != nil {
			scopedLog.Warn(
				"Ignoring annotation, applying global configuration",
				logfields.Error, err,
				logfields.Annotation, annotation.ServiceLoadBalancingAlgorithm,
				logfields.GlobalConfiguration, svcInfo.LoadBalancerAlgorithm,
			)
		}
	}

	if svc.Spec.SessionAffinity == slim_corev1.ServiceAffinityClientIP {
		svcInfo.SessionAffinity = true
		if cfg := svc.Spec.SessionAffinityConfig; cfg != nil && cfg.ClientIP != nil && cfg.ClientIP.TimeoutSeconds != nil {
			svcInfo.SessionAffinityTimeoutSec = uint32(*cfg.ClientIP.TimeoutSeconds)
		}
		if svcInfo.SessionAffinityTimeoutSec == 0 {
			svcInfo.SessionAffinityTimeoutSec = uint32(v1.DefaultClientIPServiceAffinitySeconds)
		}
		if svcInfo.SessionAffinityTimeoutSec > defaults.SessionAffinityTimeoutMaxFallback {
			scopedLog.Warn(
				"Clamping maximum possible session affinity timeout (seconds)",
				logfields.From, svcInfo.SessionAffinityTimeoutSec,
				logfields.To, defaults.SessionAffinityTimeoutMaxFallback,
			)
			svcInfo.SessionAffinityTimeoutSec = defaults.SessionAffinityTimeoutMaxFallback
		}
	}

	// TODO(brb) Get rid of this hack by moving the creation of surrogate
	// frontends to pkg/service.
	//
	// This is a hack;-( In the case of NodePort service, we need to create
	// surrogate frontends per IP protocol - one with a zero IP addr and
	// one per each public iface IP addr.
	ipv4 := option.Config.EnableIPv4 && utils.GetClusterIPByFamily(slim_corev1.IPv4Protocol, svc) != ""
	if ipv4 {
		nodePortAddrs = append(nodePortAddrs, netip.IPv4Unspecified())
	}
	ipv6 := option.Config.EnableIPv6 && utils.GetClusterIPByFamily(slim_corev1.IPv6Protocol, svc) != ""
	if ipv6 {
		nodePortAddrs = append(nodePortAddrs, netip.IPv6Unspecified())
	}

	for _, port := range svc.Spec.Ports {
		p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
		portName := loadbalancer.FEPortName(port.Name)
		if _, ok := svcInfo.Ports[portName]; !ok {
			svcInfo.Ports[portName] = p
		}

		if expType.CanExpose(slim_corev1.ServiceTypeNodePort) &&
			(svc.Spec.Type == slim_corev1.ServiceTypeNodePort || svc.Spec.Type == slim_corev1.ServiceTypeLoadBalancer) {

			if option.Config.EnableNodePort {
				proto := loadbalancer.L4Type(port.Protocol)
				port := uint16(port.NodePort)
				// This can happen if the service type is NodePort/LoadBalancer but the upstream apiserver
				// did not assign any NodePort to the service port field.
				// For example if `allocateLoadBalancerNodePorts` is set to false in the service
				// spec. For more details see -
				// https://github.com/kubernetes/enhancements/tree/master/keps/sig-network/1864-disable-lb-node-ports
				if port == uint16(0) {
					continue
				}
				id := loadbalancer.ID(0) // will be allocated by k8s_watcher

				if _, ok := svcInfo.NodePorts[portName]; !ok {
					svcInfo.NodePorts[portName] = make(map[string]*loadbalancer.L3n4AddrID)
				}

				for _, addr := range nodePortAddrs {
					if (ipv4 && addr.Is4()) || (ipv6 && addr.Is6()) {
						nodePortFE := loadbalancer.NewL3n4AddrID(proto, cmtypes.AddrClusterFrom(addr, 0), port,
							loadbalancer.ScopeExternal, id)
						svcInfo.NodePorts[portName][nodePortFE.String()] = nodePortFE
					}
				}
			}
		}
	}

	svcInfo.TopologyAware = getTopologyAware(svc)

	return svcID, svcInfo
}

// ServiceID identifies the Kubernetes service
type ServiceID struct {
	Cluster   string `json:"cluster,omitempty"`
	Name      string `json:"serviceName,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// String returns the string representation of a service ID
func (s ServiceID) String() string {
	if s.Cluster != "" {
		return fmt.Sprintf("%s/%s/%s", s.Cluster, s.Namespace, s.Name)
	}
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

// +deepequal-gen=true
type NodePortToFrontend map[string]*loadbalancer.L3n4AddrID

// Service is an abstraction for a k8s service that is composed by the frontend IP
// addresses (FEIPs) and the map of the frontend ports (Ports).
//
// +k8s:deepcopy-gen=true
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type Service struct {
	// Until deepequal-gen adds support for net.IP we need to compare this field
	// manually.
	// Whenever creating a new service we should make sure that the FrontendIPs are
	// sorted, so we always generate the same string representation.
	// +deepequal-gen=false
	FrontendIPs []net.IP
	IsHeadless  bool

	// IncludeExternal is true when external endpoints from other clusters
	// should be included
	IncludeExternal bool

	// Shared is true when the service should be exposed/shared to other clusters
	Shared bool

	// ServiceAffinity determines the preferred endpoint destination (e.g. local
	// vs remote clusters)
	//
	// Applicable values: local, remote, none (default).
	ServiceAffinity string

	// ExtTrafficPolicy controls how backends are selected for North-South traffic.
	// If set to "Local", only node-local backends are chosen.
	ExtTrafficPolicy loadbalancer.SVCTrafficPolicy

	// IntTrafficPolicy controls how backends are selected for East-West traffic.
	// If set to "Local", only node-local backends are chosen.
	IntTrafficPolicy loadbalancer.SVCTrafficPolicy

	// ForwardingMode controls whether DSR or SNAT should be used for the dispatch
	// to the backend.
	ForwardingMode loadbalancer.SVCForwardingMode

	// SourceRangesPolicy controls whether the specified loadBalancerSourceRanges
	// CIDR set defines an allow- or deny-list.
	SourceRangesPolicy loadbalancer.SVCSourceRangesPolicy

	// ProxyDelegation controls what packets should be delegated and pushed up to
	// a user space proxy unmodified from its original.
	ProxyDelegation loadbalancer.SVCProxyDelegation

	// HealthCheckNodePort defines on which port the node runs a HTTP health
	// check server which may be used by external loadbalancers to determine
	// if a node has local backends. This will only have effect if both
	// LoadBalancerIPs is not empty and ExtTrafficPolicy is SVCTrafficPolicyLocal.
	HealthCheckNodePort uint16

	Ports map[loadbalancer.FEPortName]*loadbalancer.L4Addr
	// NodePorts stores mapping for port name => NodePort frontend addr string =>
	// NodePort fronted addr. The string addr => addr indirection is to avoid
	// storing duplicates.
	NodePorts map[loadbalancer.FEPortName]NodePortToFrontend
	// K8sExternalIPs stores mapping of the endpoint in a string format to the
	// externalIP in net.IP format.
	//
	// Until deepequal-gen adds support for net.IP we need to compare this field
	// manually.
	// +deepequal-gen=false
	K8sExternalIPs map[string]net.IP

	// LoadBalancerAlgorithm indicates which backend selection algorithm to use.
	LoadBalancerAlgorithm loadbalancer.SVCLoadBalancingAlgorithm

	// LoadBalancerIPs stores LB IPs assigned to the service (string(IP) => IP).
	//
	// Until deepequal-gen adds support for net.IP we need to compare this field
	// manually.
	// +deepequal-gen=false
	LoadBalancerIPs          map[string]net.IP
	LoadBalancerSourceRanges map[string]*cidr.CIDR

	Annotations map[string]string

	Labels   map[string]string
	Selector map[string]string

	// SessionAffinity denotes whether service has the clientIP session affinity
	SessionAffinity bool
	// SessionAffinityTimeoutSeconds denotes session affinity timeout
	SessionAffinityTimeoutSec uint32

	// Type is the internal service type
	// +deepequal-gen=false
	Type loadbalancer.SVCType

	// TopologyAware denotes whether service endpoints might have topology aware
	// hints. This is used to determine if Services should be reconciled when
	// Node labels are updated. It is set to true if any of the following are
	// true:
	// * TrafficDistribution field is set to "PreferClose"
	// * service.kubernetes.io/topology-aware-hints annotation is set to "Auto"
	//   or "auto"
	// * service.kubernetes.io/topology-mode annotation is set to any value
	//   other than "Disabled"
	TopologyAware bool
}

// DeepEqual returns true if s and other are deeply equal.
func (s *Service) DeepEqual(other *Service) bool {
	if s == nil {
		return other == nil
	}

	if !s.deepEqual(other) {
		return false
	}

	if !ip.UnsortedIPListsAreEqual(s.FrontendIPs, other.FrontendIPs) {
		return false
	}

	if ((s.K8sExternalIPs != nil) && (other.K8sExternalIPs != nil)) || ((s.K8sExternalIPs == nil) != (other.K8sExternalIPs == nil)) {
		in, other := s.K8sExternalIPs, other.K8sExternalIPs
		if other == nil {
			return false
		}

		if len(in) != len(other) {
			return false
		}
		for key, inValue := range in {
			otherValue, present := other[key]
			if !present {
				return false
			}
			if !inValue.Equal(otherValue) {
				return false
			}
		}
	}

	if ((s.LoadBalancerIPs != nil) && (other.LoadBalancerIPs != nil)) || ((s.LoadBalancerIPs == nil) != (other.LoadBalancerIPs == nil)) {
		in, other := s.LoadBalancerIPs, other.LoadBalancerIPs
		if other == nil {
			return false
		}

		if len(in) != len(other) {
			return false
		}
		for key, inValue := range in {
			otherValue, present := other[key]
			if !present {
				return false
			}
			if !inValue.Equal(otherValue) {
				return false
			}
		}
	}

	return true
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

	return fmt.Sprintf("frontends:%s/ports=%s/selector=%v", s.FrontendIPs, ports, s.Selector)
}

// IsExternal returns true if the service is expected to serve out-of-cluster endpoints:
func (s Service) IsExternal() bool {
	return len(s.Selector) == 0
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
func NewService(ips []net.IP, externalIPs, loadBalancerIPs, loadBalancerSourceRanges []string,
	headless bool, extTrafficPolicy, intTrafficPolicy loadbalancer.SVCTrafficPolicy,
	healthCheckNodePort uint16, annotations, labels, selector map[string]string,
	namespace string, svcType loadbalancer.SVCType,
) *Service {
	var (
		k8sExternalIPs     map[string]net.IP
		k8sLoadBalancerIPs map[string]net.IP
	)

	loadBalancerSourceCIDRs := make(map[string]*cidr.CIDR, len(loadBalancerSourceRanges))

	for _, cidrString := range loadBalancerSourceRanges {
		cidr, _ := cidr.ParseCIDR(cidrString)
		loadBalancerSourceCIDRs[cidr.String()] = cidr
	}

	// If EnableNodePort is not true we do not want to process
	// events which only differ in external or load balancer IPs.
	// By omitting these IPs in the returned Service object, they
	// are no longer considered in equality checks and thus save
	// CPU cycles processing events Cilium will not act upon.
	if option.Config.EnableNodePort {
		k8sExternalIPs = parseIPs(externalIPs)
		k8sLoadBalancerIPs = parseIPs(loadBalancerIPs)
	}

	ip.SortIPList(ips)
	return &Service{
		FrontendIPs: ips,

		IsHeadless:          headless,
		ExtTrafficPolicy:    extTrafficPolicy,
		IntTrafficPolicy:    intTrafficPolicy,
		HealthCheckNodePort: healthCheckNodePort,

		Ports:                    map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		NodePorts:                map[loadbalancer.FEPortName]NodePortToFrontend{},
		K8sExternalIPs:           k8sExternalIPs,
		LoadBalancerIPs:          k8sLoadBalancerIPs,
		LoadBalancerSourceRanges: loadBalancerSourceCIDRs,

		Annotations: annotations,

		Labels:   labels,
		Selector: selector,
		Type:     svcType,
	}
}

// UniquePorts returns a map of all unique ports configured in the service
func (s *Service) UniquePorts() map[string]bool {
	uniqPorts := map[string]bool{}
	for _, p := range s.Ports {
		uniqPorts[p.String()] = true
	}
	return uniqPorts
}

// NewClusterService returns the serviceStore.ClusterService representing a
// Kubernetes Service
func NewClusterService(id ServiceID, k8sService *Service, k8sEndpoints *Endpoints) serviceStore.ClusterService {
	svc := serviceStore.NewClusterService(id.Name, id.Namespace)

	maps.Copy(svc.Labels, k8sService.Labels)

	maps.Copy(svc.Selector, k8sService.Selector)

	portConfig := serviceStore.PortConfiguration{}
	for portName, port := range k8sService.Ports {
		portConfig[string(portName)] = port
	}

	svc.Frontends = map[string]serviceStore.PortConfiguration{}
	for _, feIP := range k8sService.FrontendIPs {
		svc.Frontends[feIP.String()] = portConfig
	}

	svc.Backends = map[string]serviceStore.PortConfiguration{}
	for addrCluster, backend := range k8sEndpoints.Backends {
		svc.Backends[addrCluster.Addr().String()] = backend.Ports
		if backend.Hostname != "" {
			svc.Hostnames[addrCluster.Addr().String()] = backend.Hostname
		}
	}

	svc.Shared = k8sService.Shared
	svc.IncludeExternal = k8sService.IncludeExternal

	return svc
}

// ParseClusterService parses a ClusterService and returns a Service.
// ClusterService is a subset of what a Service can express,
// especially, ClusterService does not have:
// - other service types than ClusterIP
// - an explicit traffic policy, SVCTrafficPolicyCluster is assumed
// - health check node ports
// - NodePorts
// - external IPs
// - LoadBalancerIPs
// - LoadBalancerSourceRanges
// - SessionAffinity
//
// ParseClusterService() is paired with EqualsClusterService() that
// has the above wired in.
func ParseClusterService(svc *serviceStore.ClusterService) *Service {
	svcInfo := &Service{
		IsHeadless:       len(svc.Frontends) == 0,
		IncludeExternal:  true,
		Shared:           true,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		Ports:            map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
		Labels:           svc.Labels,
		Selector:         svc.Selector,
		Type:             loadbalancer.SVCTypeClusterIP,
	}

	feIPs := make([]net.IP, len(svc.Frontends))
	i := 0
	for ipStr, ports := range svc.Frontends {
		feIPs[i] = net.ParseIP(ipStr)
		for name, port := range ports {
			p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
			portName := loadbalancer.FEPortName(name)
			if _, ok := svcInfo.Ports[portName]; !ok {
				svcInfo.Ports[portName] = p
			}
		}
		i++
	}
	ip.SortIPList(feIPs)
	svcInfo.FrontendIPs = feIPs

	return svcInfo
}

// EqualsClusterService returns true the given ClusterService would parse into Service if
// ParseClusterService() would be called. This is necessary to avoid memory allocations that
// would be performed by ParseClusterService() when the service already exists.
func (s *Service) EqualsClusterService(svc *serviceStore.ClusterService) bool {
	switch {
	case (s == nil) != (svc == nil):
		return false
	case (s == nil) && (svc == nil):
		return true
	}

	feIPs := make([]net.IP, len(svc.Frontends))
	fePorts := serviceStore.PortConfiguration{}
	i := 0
	for ipStr, ports := range svc.Frontends {
		feIPs[i] = net.ParseIP(ipStr)
		for name, port := range ports {
			if _, ok := fePorts[name]; !ok {
				fePorts[name] = port
			}
		}
		i++
	}

	// These comparisons must match the ParseClusterService() function above.
	if ip.UnsortedIPListsAreEqual(s.FrontendIPs, feIPs) &&
		s.IsHeadless == (len(svc.Frontends) == 0) &&
		s.IncludeExternal &&
		s.Shared &&
		s.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyCluster &&
		s.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyCluster &&
		s.HealthCheckNodePort == 0 &&
		len(s.NodePorts) == 0 &&
		len(s.K8sExternalIPs) == 0 &&
		len(s.LoadBalancerIPs) == 0 &&
		len(s.LoadBalancerSourceRanges) == 0 &&
		maps.Equal(s.Labels, svc.Labels) &&
		maps.Equal(s.Selector, svc.Selector) &&
		!s.SessionAffinity &&
		s.SessionAffinityTimeoutSec == 0 &&
		s.Type == loadbalancer.SVCTypeClusterIP {

		if ((s.Ports == nil) != (fePorts == nil)) ||
			len(s.Ports) != len(fePorts) {
			return false
		}
		for portName, port := range s.Ports {
			oPort, ok := fePorts[string(portName)]
			if !ok {
				return false
			}
			if port.Protocol != oPort.Protocol || port.Port != oPort.Port {
				return false
			}
		}
		return true
	}
	return false
}

// CheckServiceNodeExposure returns true if the service should be installed onto the
// local node, and false if the node should ignore and not install the service.
func CheckServiceNodeExposure(localNodeStore *node.LocalNodeStore, annotations map[string]string) (bool, error) {
	if serviceAnnotationValue, serviceAnnotationExists := annotations[annotation.ServiceNodeSelectorExposure]; serviceAnnotationExists {
		ln, err := localNodeStore.Get(context.Background())
		if err != nil {
			return false, fmt.Errorf("failed to retrieve local node: %w", err)
		}

		selector, err := labels.Parse(serviceAnnotationValue)
		if err != nil {
			return false, fmt.Errorf("failed to parse node label annotation: %w", err)
		}

		if selector.Matches(labels.Set(ln.Labels)) {
			return true, nil
		}

		// prioritize any existing node-selector annotation - and return in any case
		return false, nil
	}

	if serviceAnnotationValue, serviceAnnotationExists := annotations[annotation.ServiceNodeExposure]; serviceAnnotationExists {
		ln, err := localNodeStore.Get(context.Background())
		if err != nil {
			return false, fmt.Errorf("failed to retrieve local node: %w", err)
		}

		nodeLabelValue, nodeLabelExists := ln.Labels[annotation.ServiceNodeExposure]
		if !nodeLabelExists || nodeLabelValue != serviceAnnotationValue {
			return false, nil
		}
	}

	return true, nil
}

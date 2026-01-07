// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"fmt"
	"iter"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/cache"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

var (
	zeroV4 = cmtypes.MustParseAddrCluster("0.0.0.0")
	zeroV6 = cmtypes.MustParseAddrCluster("::")

	ingressDummyAddress = cmtypes.MustParseAddrCluster("192.192.192.192")
	ingressDummyPort    = uint16(9999)
)

func isIngressDummyEndpoint(l3n4Addr loadbalancer.L3n4Addr) bool {
	// The ingress and gateway-api controllers (operator/pkg/model/translation/{gateway-api,ingress}) create
	// a dummy endpoint to force Cilium to reconcile the service. This is no longer required with this new
	// control-plane, but due to rolling upgrades we cannot remove it immediately. Hence we have the
	// special handling here to just ignore this endpoint to avoid populating the tables with unnecessary
	// data.
	return l3n4Addr.AddrCluster() == ingressDummyAddress && l3n4Addr.Port() == ingressDummyPort
}

func getAnnotationServiceForwardingMode(cfg loadbalancer.Config, svc *slim_corev1.Service) (loadbalancer.SVCForwardingMode, error) {
	if value, ok := annotation.Get(svc, annotation.ServiceForwardingMode); ok {
		val := loadbalancer.ToSVCForwardingMode(strings.ToLower(value))
		if val != loadbalancer.SVCForwardingModeUndef {
			return val, nil
		}
		return loadbalancer.ToSVCForwardingMode(cfg.LBMode), fmt.Errorf("value %q is not supported for %q", val, annotation.ServiceForwardingMode)
	}
	return loadbalancer.SVCForwardingModeUndef, nil
}

func isHeadless(svc *slim_corev1.Service) bool {
	_, headless := svc.Labels[corev1.IsHeadlessService]
	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		headless = true
	}
	return headless
}

func convertService(cfg loadbalancer.Config, extCfg loadbalancer.ExternalConfig, rawlog *slog.Logger, localNode *node.LocalNode, svc *slim_corev1.Service, source source.Source) (s *loadbalancer.Service, fes []loadbalancer.FrontendParams) {
	// Lazily construct the augmented logger as we very rarely log here. This improves throughput by 20% and avoids an allocation.
	log := sync.OnceValue(func() *slog.Logger {
		return rawlog.With(
			logfields.Service, svc.GetName(),
			logfields.K8sNamespace, svc.GetNamespace(),
		)
	})

	name := loadbalancer.NewServiceName(svc.Namespace, svc.Name)
	s = &loadbalancer.Service{
		Name:                name,
		Source:              source,
		Labels:              labels.Map2Labels(svc.Labels, string(source)),
		Selector:            svc.Spec.Selector,
		Annotations:         svc.Annotations,
		HealthCheckNodePort: uint16(svc.Spec.HealthCheckNodePort),
		ForwardingMode:      loadbalancer.SVCForwardingModeUndef,
		LoadBalancerClass:   svc.Spec.LoadBalancerClass,
	}

	if cfg.LBModeAnnotation {
		fwdMode, err := getAnnotationServiceForwardingMode(cfg, svc)
		if err == nil {
			s.ForwardingMode = fwdMode
		} else {
			log().Warn("Ignoring annotation",
				logfields.Error, err,
				logfields.Annotations, annotation.ServiceForwardingMode,
			)
		}
	}

	if localNode != nil {
		if nodeMatches, err := CheckServiceNodeExposure(localNode, svc.Annotations); err != nil {
			log().Warn("Ignoring node service exposure", logfields.Error, err)
		} else if !nodeMatches {
			return nil, nil
		}
	}

	expType, err := NewSvcExposureType(svc)
	if err != nil {
		log().Warn("Ignoring annotation",
			logfields.Error, err,
			logfields.Annotations, annotation.ServiceTypeExposure,
		)
	}

	if len(svc.Spec.Ports) > 0 {
		s.PortNames = map[string]uint16{}
		for _, port := range svc.Spec.Ports {
			s.PortNames[port.Name] = uint16(port.Port)
		}
	}

	for _, srcRange := range svc.Spec.LoadBalancerSourceRanges {
		prefix, err := netip.ParsePrefix(srcRange)
		if err != nil {
			log().Debug("Failed to parse CIDR in LoadBalancerSourceRanges, Ignoring",
				logfields.Error, err,
				logfields.LoadBalancerSourceRanges, svc.Spec.LoadBalancerSourceRanges,
			)
			continue
		}
		s.SourceRanges = append(s.SourceRanges, prefix)
	}

	switch svc.Spec.ExternalTrafficPolicy {
	case slim_corev1.ServiceExternalTrafficPolicyLocal:
		s.ExtTrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
	default:
		s.ExtTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
	}

	if svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == slim_corev1.ServiceInternalTrafficPolicyLocal {
		s.IntTrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
	} else {
		s.IntTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
	}
	// Scopes for NodePort and LoadBalancer. Either just external (policies are the same), or
	// both external and internal (when one policy is local)
	scopes := []uint8{loadbalancer.ScopeExternal}
	twoScopes := (s.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal) != (s.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal)
	if twoScopes {
		scopes = append(scopes, loadbalancer.ScopeInternal)
	}

	// SessionAffinity
	if svc.Spec.SessionAffinity == slim_corev1.ServiceAffinityClientIP {
		s.SessionAffinity = true

		s.SessionAffinityTimeout = time.Duration(int(time.Second) * int(slim_corev1.DefaultClientIPServiceAffinitySeconds))
		if cfg := svc.Spec.SessionAffinityConfig; cfg != nil && cfg.ClientIP != nil && cfg.ClientIP.TimeoutSeconds != nil && *cfg.ClientIP.TimeoutSeconds != 0 {
			s.SessionAffinityTimeout = time.Duration(int(time.Second) * int(*cfg.ClientIP.TimeoutSeconds))
		}
	}

	if s.IntTrafficPolicy != loadbalancer.SVCTrafficPolicyLocal && isTopologyAware(svc) {
		s.TrafficDistribution = loadbalancer.TrafficDistributionPreferClose
	}

	// A service that is annotated as headless has no frontends, even if the service spec contains
	// ClusterIPs etc.
	if isHeadless(svc) {
		return
	}

	// ClusterIP
	if expType.CanExpose(slim_corev1.ServiceTypeClusterIP) {
		var clusterIPs []string
		if len(svc.Spec.ClusterIPs) > 0 {
			clusterIPs = slices.Sorted(slices.Values(svc.Spec.ClusterIPs))
		} else {
			clusterIPs = []string{svc.Spec.ClusterIP}
		}

		for _, ip := range clusterIPs {
			addr, err := cmtypes.ParseAddrCluster(ip)
			if err != nil {
				log().Debug("Failed to parse ClusterIP address",
					logfields.Error, err,
					logfields.IPAddr, ip)
				continue
			}

			if (!extCfg.EnableIPv6 && addr.Is6()) || (!extCfg.EnableIPv4 && addr.Is4()) {
				log().Debug(
					"Skipping ClusterIP due to disabled IP family",
					logfields.IPv4, extCfg.EnableIPv4,
					logfields.IPv6, extCfg.EnableIPv6,
					logfields.Address, addr,
				)
				continue
			}

			for _, port := range svc.Spec.Ports {
				fe := loadbalancer.FrontendParams{
					Type:        loadbalancer.SVCTypeClusterIP,
					PortName:    loadbalancer.FEPortName(cache.Strings.Get(port.Name)),
					ServiceName: name,
					ServicePort: uint16(port.Port),
				}
				fe.Address = loadbalancer.NewL3n4Addr(
					loadbalancer.L4Type(port.Protocol),
					addr,
					uint16(port.Port),
					loadbalancer.ScopeExternal,
				)
				fes = append(fes, fe)
			}
		}
	}

	// NodePort
	// Do not reflect if KubeProxyReplacement is disabled, as it has no use and can affect NodePort service reachability.
	if extCfg.KubeProxyReplacement {
		if (svc.Spec.Type == slim_corev1.ServiceTypeNodePort || svc.Spec.Type == slim_corev1.ServiceTypeLoadBalancer) &&
			expType.CanExpose(slim_corev1.ServiceTypeNodePort) {

			for _, scope := range scopes {
				for _, family := range getIPFamilies(svc) {
					if (!extCfg.EnableIPv6 && family == slim_corev1.IPv6Protocol) ||
						(!extCfg.EnableIPv4 && family == slim_corev1.IPv4Protocol) {
						log().Debug(
							"Skipping NodePort due to disabled IP family",
							logfields.IPv4, extCfg.EnableIPv4,
							logfields.IPv6, extCfg.EnableIPv6,
							logfields.Family, family,
						)
						continue
					}
					for _, port := range svc.Spec.Ports {
						if port.NodePort == 0 {
							continue
						}

						fe := loadbalancer.FrontendParams{
							Type:        loadbalancer.SVCTypeNodePort,
							PortName:    loadbalancer.FEPortName(cache.Strings.Get(port.Name)),
							ServiceName: name,
							ServicePort: uint16(port.Port),
						}

						switch family {
						case slim_corev1.IPv4Protocol:
							fe.Address = loadbalancer.NewL3n4Addr(
								loadbalancer.L4Type(port.Protocol),
								zeroV4,
								uint16(port.NodePort),
								scope,
							)
						case slim_corev1.IPv6Protocol:
							fe.Address = loadbalancer.NewL3n4Addr(
								loadbalancer.L4Type(port.Protocol),
								zeroV6,
								uint16(port.NodePort),
								scope,
							)
						default:
							continue
						}

						fes = append(fes, fe)
					}
				}
			}
		}
	}

	// LoadBalancer
	if svc.Spec.Type == slim_corev1.ServiceTypeLoadBalancer && expType.CanExpose(slim_corev1.ServiceTypeLoadBalancer) {
		for _, ip := range svc.Status.LoadBalancer.Ingress {
			if ip.IP == "" ||
				(ip.IPMode != nil && *ip.IPMode != slim_corev1.LoadBalancerIPModeVIP) /* KEP-1860, skip non-VIP */ {
				continue
			}

			addr, err := cmtypes.ParseAddrCluster(ip.IP)
			if err != nil {
				continue
			}
			if (!extCfg.EnableIPv6 && addr.Is6()) || (!extCfg.EnableIPv4 && addr.Is4()) {
				log().Debug(
					"Skipping LoadBalancer due to disabled IP family",
					logfields.IPv4, extCfg.EnableIPv4,
					logfields.IPv6, extCfg.EnableIPv6,
					logfields.Address, addr,
				)
				continue
			}

			for _, scope := range scopes {
				for _, port := range svc.Spec.Ports {
					fe := loadbalancer.FrontendParams{
						Type:        loadbalancer.SVCTypeLoadBalancer,
						PortName:    loadbalancer.FEPortName(cache.Strings.Get(port.Name)),
						ServiceName: name,
						ServicePort: uint16(port.Port),
					}

					fe.Address = loadbalancer.NewL3n4Addr(
						loadbalancer.L4Type(port.Protocol),
						addr,
						uint16(port.Port),
						scope,
					)
					fes = append(fes, fe)
				}
			}

		}
	}

	// ExternalIP
	for _, ip := range svc.Spec.ExternalIPs {
		addr, err := cmtypes.ParseAddrCluster(ip)
		if err != nil {
			continue
		}
		if (!extCfg.EnableIPv6 && addr.Is6()) || (!extCfg.EnableIPv4 && addr.Is4()) {
			log().Debug(
				"Skipping ExternalIP due to disabled IP family",
				logfields.IPv4, extCfg.EnableIPv4,
				logfields.IPv6, extCfg.EnableIPv6,
				logfields.Address, addr,
			)
			continue
		}

		for _, port := range svc.Spec.Ports {
			fe := loadbalancer.FrontendParams{
				Type:        loadbalancer.SVCTypeExternalIPs,
				PortName:    loadbalancer.FEPortName(cache.Strings.Get(port.Name)),
				ServiceName: name,
				ServicePort: uint16(port.Port),
			}
			fe.Address = loadbalancer.NewL3n4Addr(
				loadbalancer.L4Type(port.Protocol),
				addr,
				uint16(port.Port),
				loadbalancer.ScopeExternal,
			)
			fes = append(fes, fe)
		}
	}

	return
}

func getIPFamilies(svc *slim_corev1.Service) []slim_corev1.IPFamily {
	if len(svc.Spec.IPFamilies) == 0 {
		// No IP families specified, try to deduce them from the cluster IPs
		if len(svc.Spec.ClusterIP) == 0 || svc.Spec.ClusterIP == slim_corev1.ClusterIPNone {
			return nil
		}

		ipv4, ipv6 := false, false
		if len(svc.Spec.ClusterIPs) > 0 {
			for _, cip := range svc.Spec.ClusterIPs {
				if ip.IsIPv6(net.ParseIP(cip)) {
					ipv6 = true
				} else {
					ipv4 = true
				}
			}
		} else {
			ipv6 = ip.IsIPv6(net.ParseIP(svc.Spec.ClusterIP))
			ipv4 = !ipv6
		}
		families := make([]slim_corev1.IPFamily, 0, 2)
		if ipv4 {
			families = append(families, slim_corev1.IPv4Protocol)
		}
		if ipv6 {
			families = append(families, slim_corev1.IPv4Protocol)
		}
		return families
	}
	return svc.Spec.IPFamilies
}

func convertEndpoints(rawlog *slog.Logger, cfg loadbalancer.ExternalConfig, svcName loadbalancer.ServiceName, bes iter.Seq2[cmtypes.AddrCluster, *k8s.Backend]) iter.Seq[loadbalancer.BackendParams] {
	return func(yield func(be loadbalancer.BackendParams) bool) {
		// Lazily construct the augmented logger as we very rarely log here.
		log := sync.OnceValue(func() *slog.Logger {
			return rawlog.With(
				logfields.Service, svcName.Name,
				logfields.K8sNamespace, svcName.Namespace,
			)
		})

		for addrCluster, be := range bes {
			if (!cfg.EnableIPv6 && addrCluster.Is6()) || (!cfg.EnableIPv4 && addrCluster.Is4()) {
				log().Debug(
					"Skipping Backend due to disabled IP family",
					logfields.IPv4, cfg.EnableIPv4,
					logfields.IPv6, cfg.EnableIPv6,
					logfields.Address, addrCluster,
				)
				continue
			}
			for l4Addr, portNames := range be.Ports {
				l3n4Addr := loadbalancer.NewL3n4Addr(
					l4Addr.Protocol,
					addrCluster,
					l4Addr.Port,
					loadbalancer.ScopeExternal,
				)
				if isIngressDummyEndpoint(l3n4Addr) {
					continue
				}

				// Filter out the unnamed port, if present
				if idx := slices.Index(portNames, ""); idx != -1 {
					if len(portNames) == 1 {
						portNames = nil
					} else {
						portNames = slices.Concat(portNames[:idx], portNames[idx+1:])
					}
				}

				var state loadbalancer.BackendState
				switch {
				case be.Conditions.IsReady():
					// A backend that is ready (regardless of serving and terminating) is considered
					// active. We may see backends that are ready+terminating if 'PublishNotReadyAddresses'
					// is true. While it would be more logical to set this as terminating, we're following
					// kube-proxy here and considering it as an active backend and not ignoring it even when
					// other active backends are available.
					//
					// See also kube-proxy implementation at:
					// https://github.com/kubernetes/kubernetes/blob/790393ae92e97262827d4f1fba24e8ae65bbada0/pkg/proxy/topology.go#L61
					state = loadbalancer.BackendStateActive
				case be.Conditions.IsTerminating() && !be.Conditions.IsServing():
					// A backend that is terminating and not serving should not be used for load-balancing
					// even if it's the only backend. A terminating backend is kept in the BPF maps until
					// fully removed to avoid disrupting connections.
					state = loadbalancer.BackendStateTerminatingNotServing
				case be.Conditions.IsTerminating():
					// A backend that is terminating and serving can still be used for new connections
					// when no active backends are available. A terminating backend is kept in the BPF maps until
					// fully removed to avoid disrupting connections.
					state = loadbalancer.BackendStateTerminating
				default:
					// In all other cases we mark the backend to be in maintenance. This avoids disruptions
					// to existing connections when a backend readiness is flapping.
					state = loadbalancer.BackendStateMaintenance
				}
				bep := loadbalancer.BackendParams{
					Address:   l3n4Addr,
					NodeName:  be.NodeName,
					PortNames: portNames,
					Weight:    loadbalancer.DefaultBackendWeight,
					State:     state,
				}
				if be.Zone != "" {
					bep.Zone = &loadbalancer.BackendZone{
						Zone:     be.Zone,
						ForZones: be.HintsForZones,
					}
				}
				if !yield(bep) {
					break
				}
			}
		}
	}
}

func isTopologyAware(svc *slim_corev1.Service) bool {
	return getAnnotationTopologyAwareHints(svc) ||
		(svc.Spec.TrafficDistribution != nil &&
			*svc.Spec.TrafficDistribution == corev1.ServiceTrafficDistributionPreferClose)
}

func getAnnotationTopologyAwareHints(svc *slim_corev1.Service) bool {
	// v1.DeprecatedAnnotationTopologyAwareHints has precedence over v1.AnnotationTopologyMode.
	value, ok := svc.ObjectMeta.Annotations[corev1.DeprecatedAnnotationTopologyAwareHints]
	if !ok {
		value = svc.ObjectMeta.Annotations[corev1.AnnotationTopologyMode]
	}
	return !(value == "" || value == "disabled" || value == "Disabled")
}

// CheckServiceNodeExposure returns true if the service should be installed onto the
// local node, and false if the node should ignore and not install the service.
func CheckServiceNodeExposure(localNode *node.LocalNode, annotations map[string]string) (bool, error) {
	if serviceAnnotationValue, serviceAnnotationExists := annotations[annotation.ServiceNodeSelectorExposure]; serviceAnnotationExists {
		selector, err := k8sLabels.Parse(serviceAnnotationValue)
		if err != nil {
			return false, fmt.Errorf("failed to parse node label annotation: %w", err)
		}

		if selector.Matches(k8sLabels.Set(localNode.Labels)) {
			return true, nil
		}

		// prioritize any existing node-selector annotation - and return in any case
		return false, nil
	}

	if serviceAnnotationValue, serviceAnnotationExists := annotations[annotation.ServiceNodeExposure]; serviceAnnotationExists {
		nodeLabelValue, nodeLabelExists := localNode.Labels[annotation.ServiceNodeExposure]
		if !nodeLabelExists || nodeLabelValue != serviceAnnotationValue {
			return false, nil
		}
	}

	return true, nil
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

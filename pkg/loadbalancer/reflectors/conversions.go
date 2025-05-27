// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
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
	return l3n4Addr.AddrCluster.Equal(ingressDummyAddress) && l3n4Addr.Port == ingressDummyPort
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

func convertService(cfg loadbalancer.Config, extCfg loadbalancer.ExternalConfig, rawlog *slog.Logger, localNodeStore *node.LocalNodeStore, svc *slim_corev1.Service, source source.Source) (s *loadbalancer.Service, fes []loadbalancer.FrontendParams) {
	// Lazily construct the augmented logger as we very rarely log here. This improves throughput by 20% and avoids an allocation.
	log := sync.OnceValue(func() *slog.Logger {
		return rawlog.With(
			logfields.Service, svc.GetName(),
			logfields.K8sNamespace, svc.GetNamespace(),
		)
	})

	name := loadbalancer.ServiceName{Namespace: svc.Namespace, Name: svc.Name}
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

	if localNodeStore != nil {
		if nodeMatches, err := k8s.CheckServiceNodeExposure(localNodeStore, svc.Annotations); err != nil {
			log().Warn("Ignoring node service exposure", logfields.Error, err)
		} else if !nodeMatches {
			return nil, nil

		}
	}

	expType, err := k8s.NewSvcExposureType(svc)
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
				p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
				if p == nil {
					log().Debug("Skipping ClusterIP due to bad L4 type/port",
						logfields.Port, port)
					continue
				}
				fe := loadbalancer.FrontendParams{
					Type:        loadbalancer.SVCTypeClusterIP,
					PortName:    loadbalancer.FEPortName(port.Name),
					ServiceName: name,
					ServicePort: uint16(port.Port),
				}
				fe.Address.AddrCluster = addr
				fe.Address.Scope = loadbalancer.ScopeExternal
				fe.Address.L4Addr = *p
				fes = append(fes, fe)
			}
		}
	}

	// NOTE: We always want to do ClusterIP services even when full kube-proxy replacement is disabled.
	// See https://github.com/cilium/cilium/issues/16197 for context.

	if extCfg.KubeProxyReplacement {
		// NodePort
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
							PortName:    loadbalancer.FEPortName(port.Name),
							ServiceName: name,
							ServicePort: uint16(port.Port),
						}

						switch family {
						case slim_corev1.IPv4Protocol:
							fe.Address.AddrCluster = zeroV4
						case slim_corev1.IPv6Protocol:
							fe.Address.AddrCluster = zeroV6
						default:
							continue
						}

						p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.NodePort))
						if p == nil {
							continue
						}
						fe.Address.Scope = scope
						fe.Address.L4Addr = *p
						fes = append(fes, fe)
					}
				}
			}
		}

		// LoadBalancer
		if svc.Spec.Type == slim_corev1.ServiceTypeLoadBalancer && expType.CanExpose(slim_corev1.ServiceTypeLoadBalancer) {
			for _, ip := range svc.Status.LoadBalancer.Ingress {
				if ip.IP == "" {
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
							PortName:    loadbalancer.FEPortName(port.Name),
							ServiceName: name,
							ServicePort: uint16(port.Port),
						}

						p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
						if p == nil {
							log().Debug("Skipping LoadBalancer due to bad L4 type/port",
								logfields.Port, port)
							continue
						}
						fe.Address.AddrCluster = addr
						fe.Address.Scope = scope
						fe.Address.L4Addr = *p
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
					PortName:    loadbalancer.FEPortName(port.Name),
					ServiceName: name,
					ServicePort: uint16(port.Port),
				}

				p := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
				if p == nil {
					log().Debug("Skipping ExternalIP due to bad L4 type/port",
						logfields.Port, port)
					continue
				}

				fe.Address.AddrCluster = addr
				fe.Address.Scope = loadbalancer.ScopeExternal
				fe.Address.L4Addr = *p
				fes = append(fes, fe)
			}
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

func convertEndpoints(rawlog *slog.Logger, cfg loadbalancer.ExternalConfig, ep *k8s.Endpoints) (name loadbalancer.ServiceName, out []loadbalancer.BackendParams) {
	// Lazily construct the augmented logger as we very rarely log here.
	log := sync.OnceValue(func() *slog.Logger {
		return rawlog.With(
			logfields.Service, ep.GetName(),
			logfields.K8sNamespace, ep.GetNamespace(),
		)
	})

	name = loadbalancer.ServiceName{
		Name:      ep.ServiceID.Name,
		Namespace: ep.ServiceID.Namespace,
	}

	// k8s.Endpoints may have the same backend address multiple times
	// with a different port name. Collapse them down into single
	// entry.
	type entry struct {
		portNames []string
		backend   *k8s.Backend
	}
	entries := map[loadbalancer.L3n4Addr]entry{}

	for addrCluster, be := range ep.Backends {
		if (!cfg.EnableIPv6 && addrCluster.Is6()) || (!cfg.EnableIPv4 && addrCluster.Is4()) {
			log().Debug(
				"Skipping Backend due to disabled IP family",
				logfields.IPv4, cfg.EnableIPv4,
				logfields.IPv6, cfg.EnableIPv6,
				logfields.Address, addrCluster,
			)
			continue
		}
		for portName, l4Addr := range be.Ports {
			l3n4Addr := loadbalancer.L3n4Addr{
				AddrCluster: addrCluster,
				L4Addr:      *l4Addr,
			}
			if isIngressDummyEndpoint(l3n4Addr) {
				continue
			}
			portNames := entries[l3n4Addr].portNames
			if portName != "" {
				portNames = append(portNames, portName)
			}
			entries[l3n4Addr] = entry{
				portNames: portNames,
				backend:   be,
			}
		}
	}
	for l3n4Addr, entry := range entries {
		state := loadbalancer.BackendStateActive
		if entry.backend.Terminating {
			state = loadbalancer.BackendStateTerminating
		}
		be := loadbalancer.BackendParams{
			Address:   l3n4Addr,
			NodeName:  entry.backend.NodeName,
			PortNames: entry.portNames,
			Weight:    loadbalancer.DefaultBackendWeight,
			Zone:      entry.backend.Zone,
			ForZones:  entry.backend.HintsForZones,
			State:     state,
		}
		out = append(out, be)
	}
	return
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

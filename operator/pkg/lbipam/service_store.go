// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"net"
	"net/netip"
	"slices"

	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
)

type serviceStore struct {
	// List of services which have received all IPs they requested
	satisfied map[resource.Key]*ServiceView
	// List of services which have one or more IPs which were requested but not allocated
	unsatisfied map[resource.Key]*ServiceView
}

func NewServiceStore() serviceStore {
	return serviceStore{
		satisfied:   make(map[resource.Key]*ServiceView),
		unsatisfied: make(map[resource.Key]*ServiceView),
	}
}

func (ss *serviceStore) GetService(key resource.Key) (serviceView *ServiceView, found, satisfied bool) {
	serviceView, found = ss.satisfied[key]
	if found {
		return serviceView, true, true
	}

	serviceView, found = ss.unsatisfied[key]
	if found {
		return serviceView, true, false
	}

	return nil, false, false
}

func (ss *serviceStore) Upsert(serviceView *ServiceView) {
	if serviceView.isSatisfied() {
		delete(ss.unsatisfied, serviceView.Key)
		ss.satisfied[serviceView.Key] = serviceView
	} else {
		delete(ss.satisfied, serviceView.Key)
		ss.unsatisfied[serviceView.Key] = serviceView
	}
}

func (ss *serviceStore) Delete(key resource.Key) {
	delete(ss.satisfied, key)
	delete(ss.unsatisfied, key)
}

// ServiceView is the LB IPAM's view of the service, the minimal amount of info we need about it.
type ServiceView struct {
	Key    resource.Key
	Labels slim_labels.Set

	Generation int64
	Status     *slim_core_v1.ServiceStatus

	SharingKey            string
	SharingCrossNamespace []string
	// These required to determine if a service conflicts with another for sharing an ip
	ExternalTrafficPolicy slim_core_v1.ServiceExternalTrafficPolicy
	Ports                 []slim_core_v1.ServicePort
	Namespace             string
	Selector              map[string]string

	// The specific IPs requested by the service
	RequestedIPs []netip.Addr
	// The IP families requested by the service
	RequestedFamilies struct {
		IPv4 bool
		IPv6 bool
	}
	// The IPs we have allocated for this IP
	AllocatedIPs []ServiceViewIP
}

// isCompatible checks if two services are compatible for sharing an IP.
func (sv *ServiceView) isCompatible(osv *ServiceView) (bool, string) {
	// They have the same sharing key.
	if sv.SharingKey != osv.SharingKey {
		return false, "different sharing key"
	}

	// Services are namespaced, so services are only compatible if they are in the same namespace.
	// This is for security reasons, otherwise a bad tenant could use a service in another namespace.
	// We still allow cross-namespace sharing if specifically allowed on both services.
	if sv.Namespace != osv.Namespace {
		if !slices.Contains(sv.SharingCrossNamespace, osv.Namespace) && !slices.Contains(sv.SharingCrossNamespace, ciliumSvcLBISKCNWildward) || !slices.Contains(osv.SharingCrossNamespace, sv.Namespace) && !slices.Contains(osv.SharingCrossNamespace, ciliumSvcLBISKCNWildward) {
			return false, "different and not permitted namespace"
		}
	}

	// Compatible services don't have any overlapping ports.
	// NOTE: Normally we would also consider the protocol, but the Cilium datapath can't differentiate between
	// 	     protocols, so we don't either for this purpose. https://github.com/cilium/cilium/issues/9207
	for _, port1 := range sv.Ports {
		for _, port2 := range osv.Ports {
			if port1.Port == port2.Port {
				return false, "same port"
			}
		}
	}

	// Compatible services have the same external traffic policy.
	// If this were not the case, then we could end up in a situation directing traffic to a node which doesn't
	// have the pod running on it for one of the services with an `local` external traffic policy.
	if sv.ExternalTrafficPolicy != osv.ExternalTrafficPolicy {
		return false, "different ExternalTrafficPolicy"
	}

	// If both services have a 'local' external traffic policy, then they must select the same set of pods.
	// If this were not the case, then we could end up in a situation directing traffic to a node which doesn't
	// have the pod running on it for one of the services.
	if sv.ExternalTrafficPolicy == slim_core_v1.ServiceExternalTrafficPolicyLocal {
		// If any of the two service doesn't select any pods with the selector, it likely uses an endpoints object to
		// link the service to pods. LB-IPAM isn't smart enough to handle this case (yet), so we don't allow it.
		if len(sv.Selector) == 0 || len(osv.Selector) == 0 {
			return false, "compatible ExternalTrafficPolicy local but selecting different set of pods"
		}

		// If both use selectors, and they are not the same, then the services are not compatible.
		if !maps.Equal(sv.Selector, osv.Selector) {
			return false, "compatible ExternalTrafficPolicy local but selecting different set of pods"
		}
	}

	// If we can't find any reason to disqualify the services, then they are compatible.
	return true, ""
}

func (sv *ServiceView) isSatisfied() bool {
	// If the service requests specific IPs
	if len(sv.RequestedIPs) > 0 {
		for _, reqIP := range sv.RequestedIPs {
			// If reqIP doesn't exist in the list of assigned IPs
			if slices.IndexFunc(sv.Status.LoadBalancer.Ingress, func(in slim_core_v1.LoadBalancerIngress) bool {
				addr, err := netip.ParseAddr(in.IP)
				if err != nil {
					return false
				}
				return addr.Compare(reqIP) == 0
			}) == -1 {
				return false
			}
		}

		return true
	}

	// No specific requests are made, check that all requested families are assigned
	hasIPv4 := false
	hasIPv6 := false
	for _, assigned := range sv.Status.LoadBalancer.Ingress {
		if net.ParseIP(assigned.IP).To4() == nil {
			hasIPv6 = true
		} else {
			hasIPv4 = true
		}
	}

	// We are unsatisfied if we requested IPv4 and didn't get it or we requested IPv6 and didn't get it
	unsatisfied := (sv.RequestedFamilies.IPv4 && !hasIPv4) || (sv.RequestedFamilies.IPv6 && !hasIPv6)
	return !unsatisfied
}

// ServiceViewIP is the IP and from which range it was allocated
type ServiceViewIP struct {
	IP     netip.Addr
	Origin *LBRange
}

// svcLabels clones the services labels and adds a number of internal labels which can be used to select
// specific services and/or namespaces using the label selectors.
func svcLabels(svc *slim_core_v1.Service) slim_labels.Set {
	clone := maps.Clone(svc.Labels)
	if clone == nil {
		clone = make(map[string]string)
	}
	clone[serviceNameLabel] = svc.Name
	clone[serviceNamespaceLabel] = svc.Namespace
	return clone
}

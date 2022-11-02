// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"net"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

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

	// The specific IPs requested by the service
	RequestedIPs []net.IP
	// The IP families requested by the service
	RequestedFamilies struct {
		IPv4 bool
		IPv6 bool
	}
	// The IPs we have allocated for this IP
	AllocatedIPs []ServiceViewIP
}

func (sv *ServiceView) isSatisfied() bool {
	// If the service requests specific IPs
	if len(sv.RequestedIPs) > 0 {
		for _, reqIP := range sv.RequestedIPs {
			// If reqIP doesn't exist in the list of assigned IPs
			if slices.IndexFunc(sv.Status.LoadBalancer.Ingress, func(in slim_core_v1.LoadBalancerIngress) bool {
				return net.ParseIP(in.IP).Equal(reqIP)
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
	IP     net.IP
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

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"strings"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func (svc *Service) GetLBAlgorithmAnnotation() loadbalancer.SVCLoadBalancingAlgorithm {
	return loadbalancer.ToSVCLoadBalancingAlgorithm(svc.Annotations[annotation.ServiceLoadBalancingAlgorithm])
}

func (svc *Service) GetAnnotations() map[string]string {
	return svc.Annotations
}

func (svc *Service) GetIncludeExternalAnnotation() bool {
	if value, ok := annotation.Get(svc, annotation.GlobalService, annotation.GlobalServiceAlias); ok {
		return strings.ToLower(value) == "true"
	}
	return false
}

func (svc *Service) GetSharedAnnotation() bool {
	// The SharedService annotation is ignored if the service is not declared as global.
	if !svc.GetIncludeExternalAnnotation() {
		return false
	}

	if value, ok := annotation.Get(svc, annotation.SharedService, annotation.SharedServiceAlias); ok {
		return strings.ToLower(value) == "true"
	}

	// A global service is marked as shared by default.
	return true
}

type ServiceAffinity string

const (
	ServiceAffinityNone   = ServiceAffinity("")
	ServiceAffinityLocal  = ServiceAffinity("local")
	ServiceAffinityRemote = ServiceAffinity("remote")
)

func (svc *Service) GetServiceAffinityAnnotation() ServiceAffinity {
	// The ServiceAffinity annotation is ignored if the service is not declared as global.
	if !svc.GetIncludeExternalAnnotation() {
		return ServiceAffinityNone
	}
	if value, ok := annotation.Get(svc, annotation.ServiceAffinity, annotation.ServiceAffinityAlias); ok {
		switch ServiceAffinity(strings.ToLower(value)) {
		case ServiceAffinityLocal:
			return ServiceAffinityLocal
		case ServiceAffinityRemote:
			return ServiceAffinityRemote
		}
	}
	return ServiceAffinityNone
}

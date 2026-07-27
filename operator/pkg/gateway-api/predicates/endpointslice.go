// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package predicates

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	gwModel "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
)

// IsManagedFrontendEndpointSlice returns true when the EndpointSlice is a
// frontend slice managed by the cilium-operator (created by the Gateway
// translator for an L4 listener). The check is based on the standard
// EndpointSlice managed-by label.
func IsManagedFrontendEndpointSlice(obj client.Object) bool {
	if obj == nil {
		return false
	}
	return obj.GetLabels()[gwModel.EndpointSliceManagedByLabel] == gwModel.EndpointSliceManagedByValue
}

// ManagedFrontendEndpointSlice is a predicate that only admits managed frontend
// EndpointSlices.
func ManagedFrontendEndpointSlice() predicate.Predicate {
	return predicate.NewPredicateFuncs(IsManagedFrontendEndpointSlice)
}

// NonManagedEndpointSlice is a predicate that admits any EndpointSlice that is
// not a managed frontend slice (i.e. a backend slice produced by upstream
// kube-controller-manager or another controller).
func NonManagedEndpointSlice() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return !IsManagedFrontendEndpointSlice(obj)
	})
}

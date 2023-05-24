// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	corev1 "k8s.io/api/core/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// isReferenceAllowed returns true if the reference is allowed by the reference grant.
// TODO(tam): only HTTP and TLS with Service is supported right now.
// We need to support other routes (e.g. grpc, etc.) later.
func IsBackendReferenceAllowed(originatingNamespace string, be gatewayv1beta1.BackendRef, grants []gatewayv1beta1.ReferenceGrant) bool {
	ns := NamespaceDerefOr(be.Namespace, originatingNamespace)
	if originatingNamespace == ns {
		return true // same namespace is always allowed
	}

	for _, g := range grants {
		if g.Namespace != ns {
			continue
		}
		for _, from := range g.Spec.From {
			if ((from.Group == gatewayv1beta1.GroupName && from.Kind == "HTTPRoute") ||
				(from.Group == gatewayv1alpha2.GroupName && from.Kind == "TLSRoute")) &&
				(string)(from.Namespace) == originatingNamespace {
				for _, to := range g.Spec.To {
					if to.Group == corev1.GroupName && to.Kind == "Service" &&
						(to.Name == nil || string(*to.Name) == string(be.Name)) {
						return true
					}
				}
			}
		}
	}
	return false
}

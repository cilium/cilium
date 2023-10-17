// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	corev1 "k8s.io/api/core/v1"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// IsBackendReferenceAllowed returns true if the backend reference is allowed by the reference grant.
func IsBackendReferenceAllowed(originatingNamespace string, be gatewayv1.BackendRef, gvk schema.GroupVersionKind, grants []gatewayv1beta1.ReferenceGrant) bool {
	return isReferenceAllowed(originatingNamespace, string(be.Name), be.Namespace, gvk, corev1.SchemeGroupVersion.WithKind("Service"), grants)
}

// IsSecretReferenceAllowed returns true if the secret reference is allowed by the reference grant.
func IsSecretReferenceAllowed(originatingNamespace string, sr gatewayv1.SecretObjectReference, gvk schema.GroupVersionKind, grants []gatewayv1beta1.ReferenceGrant) bool {
	return isReferenceAllowed(originatingNamespace, string(sr.Name), sr.Namespace, gvk, corev1.SchemeGroupVersion.WithKind("Secret"), grants)
}

func isReferenceAllowed(originatingNamespace, name string, namespace *gatewayv1.Namespace, fromGVK, toGVK schema.GroupVersionKind, grants []gatewayv1beta1.ReferenceGrant) bool {
	ns := NamespaceDerefOr(namespace, originatingNamespace)
	if originatingNamespace == ns {
		return true // same namespace is always allowed
	}

	for _, g := range grants {
		if g.Namespace != ns {
			continue
		}
		for _, from := range g.Spec.From {
			if (from.Group == gatewayv1.Group(fromGVK.Group) && from.Kind == gatewayv1.Kind(fromGVK.Kind)) &&
				(string)(from.Namespace) == originatingNamespace {
				for _, to := range g.Spec.To {
					if to.Group == gatewayv1.Group(toGVK.Group) && to.Kind == gatewayv1.Kind(toGVK.Kind) &&
						(to.Name == nil || string(*to.Name) == name) {
						return true
					}
				}
			}
		}
	}
	return false
}

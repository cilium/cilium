// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func NamespaceDerefOr(namespace *gatewayv1.Namespace, defaultNamespace string) string {
	if namespace != nil && *namespace != "" {
		return string(*namespace)
	}
	return defaultNamespace
}

// DerefOr dereferences a pointer and returns its value, or the default if nil.
func DerefOr[T any](ptr *T, def T) T {
	if ptr != nil {
		return *ptr
	}
	return def
}

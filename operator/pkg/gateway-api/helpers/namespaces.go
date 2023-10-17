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

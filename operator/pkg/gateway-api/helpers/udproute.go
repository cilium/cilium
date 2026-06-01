// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// HasUDPRouteSupport returns if the UDPRoute CRD is supported.
// This checks if the Gateway API v1alpha2 UDPRoute CRD is registered in the client scheme.
func HasUDPRouteSupport(scheme *runtime.Scheme) bool {
	return scheme.Recognizes(gatewayv1alpha2.SchemeGroupVersion.WithKind("UDPRoute"))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// HasTCPRouteSupport returns if the TCPRoute CRD is supported.
// This checks if the Gateway API v1 TCPRoute CRD is registered in the client scheme.
func HasTCPRouteSupport(scheme *runtime.Scheme) bool {
	return scheme.Recognizes(gatewayv1.SchemeGroupVersion.WithKind("TCPRoute"))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// HasTCPRouteSupport returns if the TCPRoute CRD is supported.
// This checks if the Gateway API v1alpha2 TCPRoute CRD is registered in the client scheme.
func HasTCPRouteSupport(scheme *runtime.Scheme) bool {
	return scheme.Recognizes(GatewayV1Alpha2GVK("TCPRoute"))
}

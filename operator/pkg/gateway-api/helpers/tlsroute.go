// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// HasTLSRouteSupport returns if the TLSRoute CRD is supported.
// This checks if the Gateway API v1alpha2 TLSRoute CRD is registered in the client scheme
// and it is expected that it is registered only if the TLSRoute
// CRD has been installed prior to the client setup.
func HasTLSRouteSupport(scheme *runtime.Scheme) bool {
	return scheme.Recognizes(GatewayV1GVK("TLSRoute"))
}

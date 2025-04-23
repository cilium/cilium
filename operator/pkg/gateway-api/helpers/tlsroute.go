// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// HasTLSRouteSupport returns if the TLSRoute CRD is supported.
// This checks if the Gateway API v1alpha2 TLSRoute CRD is registered in the client scheme
// and it is expected that it is registered only if the TLSRoute
// CRD has been installed prior to the client setup.
func HasTLSRouteSupport(scheme *runtime.Scheme) bool {
	return scheme.Recognizes(gatewayv1alpha2.SchemeGroupVersion.WithKind("TLSRoute"))
}

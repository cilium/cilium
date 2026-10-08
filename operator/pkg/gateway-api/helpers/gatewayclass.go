// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// GatewayClassMatchesControllerName is a closure that returns a function that satisfies
// the controller-runtime predicate signature, allowing this to be used in predicate
// contexts as well as others.
func GatewayClassMatchesControllerName(controllerName string) func(object client.Object) bool {
	return func(object client.Object) bool {
		gwc, ok := object.(*gatewayv1.GatewayClass)
		if !ok {
			return false
		}
		return string(gwc.Spec.ControllerName) == controllerName
	}
}

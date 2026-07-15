// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// IndexGatewayClassByCiliumGatewayClassConfig indexes GatewayClass objects by
// the referenced CiliumGatewayClassConfig for the given controller.
func IndexGatewayClassByCiliumGatewayClassConfig(controllerName gatewayv1.GatewayController) client.IndexerFunc {
	return func(rawObj client.Object) []string {
		gwc, ok := rawObj.(*gatewayv1.GatewayClass)
		if !ok {
			return nil
		}

		if gwc.Spec.ControllerName != controllerName {
			return nil
		}

		if gwc.Spec.ParametersRef == nil ||
			gwc.Spec.ParametersRef.Group != ciliumv2alpha1.CustomResourceDefinitionGroup ||
			gwc.Spec.ParametersRef.Kind != ciliumv2alpha1.CGCCKindDefinition ||
			gwc.Spec.ParametersRef.Namespace == nil {
			return nil
		}

		return []string{types.NamespacedName{
			Namespace: string(*gwc.Spec.ParametersRef.Namespace),
			Name:      gwc.Spec.ParametersRef.Name,
		}.String()}
	}
}

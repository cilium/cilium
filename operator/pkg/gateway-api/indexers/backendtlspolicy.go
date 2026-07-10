// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func IndexBTLSPolicyByConfigMap(rawObj client.Object) []string {
	btlsp := rawObj.(*gatewayv1.BackendTLSPolicy)
	var configMaps []string

	for _, cfgMapRef := range btlsp.Spec.Validation.CACertificateRefs {
		if cfgMapRef.Group != "" || cfgMapRef.Kind != (gatewayv1.Kind("ConfigMap")) {
			// Don't index anything other than a ConfigMap
			continue
		}
		configMaps = append(configMaps, types.NamespacedName{
			Name:      string(cfgMapRef.Name),
			Namespace: btlsp.GetNamespace(),
		}.String())
	}
	return configMaps
}

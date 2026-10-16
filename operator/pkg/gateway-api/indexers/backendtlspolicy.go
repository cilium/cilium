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

func IndexBTLSPolicyBySecret(rawObj client.Object) []string {
	btlsp := rawObj.(*gatewayv1.BackendTLSPolicy)
	var secrets []string

	for _, secretRef := range btlsp.Spec.Validation.CACertificateRefs {
		if secretRef.Group != "" || secretRef.Kind != (gatewayv1.Kind("Secret")) {
			// Don't index anything other than a Secret
			continue
		}
		secrets = append(secrets, types.NamespacedName{
			Name:      string(secretRef.Name),
			Namespace: btlsp.GetNamespace(),
		}.String())
	}
	return secrets
}

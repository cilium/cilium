// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// FirstFrontendTLSCACertificateRef returns the only frontend TLS CA reference
// supported by Gateway API Core conformance.
func FirstFrontendTLSCACertificateRef(validation *gatewayv1.FrontendTLSValidation) (gatewayv1.ObjectReference, bool) {
	if validation == nil || len(validation.CACertificateRefs) == 0 {
		return gatewayv1.ObjectReference{}, false
	}
	return validation.CACertificateRefs[0], true
}

func FrontendTLSValidationForPort(gw *gatewayv1.Gateway, port gatewayv1.PortNumber) *gatewayv1.FrontendTLSValidation {
	frontend := FrontendTLSConfig(gw)

	if frontend == nil {
		return nil
	}

	for _, perPort := range frontend.PerPort {
		if perPort.Port == port {
			// A matching per-port config overrides the default,
			// including when Validation is nil.
			return perPort.TLS.Validation
		}
	}

	return frontend.Default.Validation
}

func FrontendTLSConfigMapRefSet(gw *gatewayv1.Gateway) map[types.NamespacedName]struct{} {
	res := map[types.NamespacedName]struct{}{}

	frontend := FrontendTLSConfig(gw)
	if frontend == nil {
		return nil
	}

	add := func(validation *gatewayv1.FrontendTLSValidation) {
		ref, ok := FirstFrontendTLSCACertificateRef(validation)
		if !ok || !IsObjectRefConfigMap(ref) {
			return
		}

		res[types.NamespacedName{
			Namespace: string(NamespaceDerefOr(ref.Namespace, gw.Namespace)),
			Name:      string(ref.Name),
		}] = struct{}{}
	}

	add(frontend.Default.Validation)
	for _, perPort := range frontend.PerPort {
		add(perPort.TLS.Validation)
	}

	return res
}

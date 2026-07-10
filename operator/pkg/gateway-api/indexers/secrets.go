// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func IndexGatewayBySecret(rawObj client.Object) []string {
	gw := rawObj.(*gatewayv1.Gateway)

	var keys []string
	for _, l := range gw.Spec.Listeners {
		keys = append(keys, listenerSecretKeys(l.TLS, gw.GetNamespace())...)
	}
	return keys
}

func IndexListenerSetBySecret(rawObj client.Object) []string {
	ls := rawObj.(*gatewayv1.ListenerSet)

	var keys []string
	for _, l := range ls.Spec.Listeners {
		keys = append(keys, listenerSecretKeys(l.TLS, ls.GetNamespace())...)
	}
	return keys
}

func listenerSecretKeys(tls *gatewayv1.ListenerTLSConfig, ownerNamespace string) []string {
	if tls == nil {
		return nil
	}

	var keys []string
	for _, cert := range tls.CertificateRefs {
		if !helpers.IsSecret(cert) {
			continue
		}
		keys = append(keys, types.NamespacedName{
			Name:      string(cert.Name),
			Namespace: helpers.NamespaceDerefOr(cert.Namespace, ownerNamespace),
		}.String())
	}
	return keys
}

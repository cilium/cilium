// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"log/slog"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// indexTLSRoutebyBackendService takes a single TLSRoute and  returns all referenced backend service full names (`namespace/name`)
// to add to the relevant index.
func GenerateIndexerTLSRoutebyBackendService(c client.Client, logger *slog.Logger) client.IndexerFunc {
	return func(rawObj client.Object) []string {
		route := rawObj.(*gatewayv1.TLSRoute)
		var backendServices []string

		for _, rule := range route.Spec.Rules {
			for _, backend := range rule.BackendRefs {
				namespace := helpers.NamespaceDerefOr(backend.Namespace, route.Namespace)
				backendServiceName, err := helpers.GetBackendServiceName(c, namespace, backend.BackendObjectReference)
				if err != nil {
					logger.Error("Failed to get backend service name",
						logfields.LogSubsys, logfields.TLSRoute,
						logfields.TLSRoute, client.ObjectKeyFromObject(rawObj),
						logfields.Error, err)
					continue
				}
				backendServices = append(backendServices,
					types.NamespacedName{
						Namespace: helpers.NamespaceDerefOr(backend.Namespace, route.Namespace),
						Name:      backendServiceName,
					}.String(),
				)
			}
		}

		return backendServices
	}
}

// IndexTLSRouteByGateway takes a single TLSRoute and returns all referenced Gateway object full names (`namespace/name`)
// to add to the relevant index.
//
// Note that this does _not_ filter to only Cilium-relevant Gateways.
func IndexTLSRouteByGateway(rawObj client.Object) []string {
	route := rawObj.(*gatewayv1.TLSRoute)
	var gateways []string
	for _, parent := range route.Spec.ParentRefs {
		if !helpers.IsGateway(parent) {
			continue
		}
		gateways = append(gateways,
			types.NamespacedName{
				Namespace: helpers.NamespaceDerefOr(parent.Namespace, route.Namespace),
				Name:      string(parent.Name),
			}.String(),
		)
	}
	return gateways
}

// IndexTLSRouteByListenerSet indexes TLSRoutes by all ListenerSet parents
// referenced in the object, returning ListenerSet full names (`namespace/name`).
func IndexTLSRouteByListenerSet(rawObj client.Object) []string {
	route := rawObj.(*gatewayv1.TLSRoute)
	var listenerSets []string
	for _, parent := range route.Spec.ParentRefs {
		if !helpers.IsListenerSet(parent) {
			continue
		}
		listenerSets = append(listenerSets,
			types.NamespacedName{
				Namespace: helpers.NamespaceDerefOr(parent.Namespace, route.Namespace),
				Name:      string(parent.Name),
			}.String(),
		)
	}
	return listenerSets
}

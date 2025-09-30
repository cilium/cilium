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

// IndexHTTPRouteByGateway is a client.IndexerFunc that takes a single HTTPRoute and returns all
// referenced Gateway object full names (`namespace/name`) to add to the relevant index.
//
// Note that this does _not_ filter to only Cilium-relevant Gateways.
func IndexHTTPRouteByGateway(rawObj client.Object) []string {
	hr := rawObj.(*gatewayv1.HTTPRoute)
	var gateways []string
	for _, parent := range hr.Spec.ParentRefs {
		if !helpers.IsGateway(parent) {
			continue
		}
		gateways = append(gateways,
			types.NamespacedName{
				Namespace: helpers.NamespaceDerefOr(parent.Namespace, hr.Namespace),
				Name:      string(parent.Name),
			}.String(),
		)
	}
	return gateways
}

// IndexHTTPRouteByGammaService is a client.IndexerFunc that takes a single HTTPRoute and returns all
// referenced Service object full names (`namespace/name`) to add to the relevant index.
func IndexHTTPRouteByGammaService(rawObj client.Object) []string {
	services := []string{}
	hr, ok := rawObj.(*gatewayv1.HTTPRoute)
	if !ok {
		return services
	}
	for _, parent := range hr.Spec.ParentRefs {
		if !helpers.IsGammaService(parent) {
			continue
		}
		services = append(services,
			types.NamespacedName{
				Namespace: helpers.NamespaceDerefOr(parent.Namespace, hr.Namespace),
				Name:      string(parent.Name),
			}.String(),
		)
	}
	return services
}

// GenerateIndexerHTTPRouteByBackendService makes a client.IndexerFunc that takes a single HTTPRoute and
// returns all referenced backend service full names (`namespace/name`) to add to the relevant index.
func GenerateIndexerHTTPRouteByBackendService(c client.Client, logger *slog.Logger) client.IndexerFunc {
	return func(rawObj client.Object) []string {
		route, ok := rawObj.(*gatewayv1.HTTPRoute)
		if !ok {
			return nil
		}
		var backendServices []string

		for _, rule := range route.Spec.Rules {
			for _, backend := range rule.BackendRefs {
				namespace := helpers.NamespaceDerefOr(backend.Namespace, route.Namespace)
				backendServiceName, err := helpers.GetBackendServiceName(c, namespace, backend.BackendObjectReference)
				if err != nil {
					logger.Error("Failed to get backend service name",
						logfields.LogSubsys, logfields.HTTPRoute,
						logfields.HTTPRoute, client.ObjectKeyFromObject(rawObj),
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

// IndexHTTPRouteByBackendServiceImport is a client.IndexerFunx that takes a single HTTPRoute and
// returns all referenced backend ServiceImport full names (`namespace/name`) to add to the relevant index.
func IndexHTTPRouteByBackendServiceImport(rawObj client.Object) []string {
	hr, ok := rawObj.(*gatewayv1.HTTPRoute)
	if !ok {
		return nil
	}
	var backendServiceImports []string

	for _, rule := range hr.Spec.Rules {
		for _, backend := range rule.BackendRefs {
			if !helpers.IsServiceImport(backend.BackendObjectReference) {
				continue
			}
			backendServiceImports = append(backendServiceImports,
				types.NamespacedName{
					Namespace: helpers.NamespaceDerefOr(backend.Namespace, hr.Namespace),
					Name:      string(backend.Name),
				}.String(),
			)
		}
	}
	return backendServiceImports
}

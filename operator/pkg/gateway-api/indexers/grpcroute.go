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

// IndexGRPCRouteByGateway is a client.IndexerFunc that takes a single GRPCRoute and returns all
// referenced Gateway object full names (`namespace/name`) to add to the relevant index.
//
// Note that this does _not_ filter to only Cilium-relevant Gateways.
func IndexGRPCRouteByGateway(rawObj client.Object) []string {
	route := rawObj.(*gatewayv1.GRPCRoute)
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

// IndexGRPCRouteByGammaService is a client.IndexerFunc that takes a single GRPCRoute and returns all
// referenced Service object full names (`namespace/name`) to add to the relevant index.
func IndexGRPCRouteByGammaService(rawObj client.Object) []string {
	services := []string{}
	route, ok := rawObj.(*gatewayv1.GRPCRoute)
	if !ok {
		return services
	}
	for _, parent := range route.Spec.ParentRefs {
		if !helpers.IsGammaService(parent) {
			continue
		}
		services = append(services,
			types.NamespacedName{
				Namespace: helpers.NamespaceDerefOr(parent.Namespace, route.Namespace),
				Name:      string(parent.Name),
			}.String(),
		)
	}
	return services
}

// GenerateIndexerGRPCRoutebyBackendService takes a single GRPCRoute and  returns all referenced backend service full names (`namespace/name`)
// to add to the relevant index.
func GenerateIndexerGRPCRoutebyBackendService(c client.Client, logger *slog.Logger) client.IndexerFunc {
	return func(rawObj client.Object) []string {
		route := rawObj.(*gatewayv1.GRPCRoute)
		var backendServices []string

		for _, rule := range route.Spec.Rules {
			for _, backend := range rule.BackendRefs {
				namespace := helpers.NamespaceDerefOr(backend.Namespace, route.Namespace)
				backendServiceName, err := helpers.GetBackendServiceName(c, namespace, backend.BackendObjectReference)
				if err != nil {
					logger.Error("Failed to get backend service name",
						logfields.LogSubsys, logfields.GRPCRoute,
						logfields.Resource, client.ObjectKeyFromObject(rawObj),
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

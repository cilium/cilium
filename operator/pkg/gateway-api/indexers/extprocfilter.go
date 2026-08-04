// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	extProcFilterGroup = "cilium.io"
	extProcFilterKind  = "CiliumEnvoyExtProcFilter"
)

// IndexHTTPRouteByExtProcFilter is a client.IndexerFunc that takes a single HTTPRoute
// and returns the full names (`namespace/name`) of all CiliumEnvoyExtProcFilters
// referenced via ExtensionRef filters on that HTTPRoute.
//
// ExtensionRef filters are same-namespace only (gatewayv1.LocalObjectReference has
// no Namespace field), so the referenced filter always lives in the route's own
// namespace.
func IndexHTTPRouteByExtProcFilter(rawObj client.Object) []string {
	hr, ok := rawObj.(*gatewayv1.HTTPRoute)
	if !ok {
		return nil
	}
	var filters []string
	for _, rule := range hr.Spec.Rules {
		for _, f := range rule.Filters {
			if f.Type != gatewayv1.HTTPRouteFilterExtensionRef || f.ExtensionRef == nil {
				continue
			}
			if string(f.ExtensionRef.Group) != extProcFilterGroup || string(f.ExtensionRef.Kind) != extProcFilterKind {
				continue
			}
			filters = append(filters, types.NamespacedName{
				Namespace: hr.Namespace,
				Name:      string(f.ExtensionRef.Name),
			}.String())
		}
	}
	return filters
}

// IndexGRPCRouteByExtProcFilter is the GRPCRoute equivalent of
// IndexHTTPRouteByExtProcFilter.
func IndexGRPCRouteByExtProcFilter(rawObj client.Object) []string {
	gr, ok := rawObj.(*gatewayv1.GRPCRoute)
	if !ok {
		return nil
	}
	var filters []string
	for _, rule := range gr.Spec.Rules {
		for _, f := range rule.Filters {
			if f.Type != gatewayv1.GRPCRouteFilterExtensionRef || f.ExtensionRef == nil {
				continue
			}
			if string(f.ExtensionRef.Group) != extProcFilterGroup || string(f.ExtensionRef.Kind) != extProcFilterKind {
				continue
			}
			filters = append(filters, types.NamespacedName{
				Namespace: gr.Namespace,
				Name:      string(f.ExtensionRef.Name),
			}.String())
		}
	}
	return filters
}

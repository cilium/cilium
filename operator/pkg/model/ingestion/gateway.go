// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/model"
)

// Input is the input for GatewayAPI.
type Input struct {
	GatewayClass gatewayv1beta1.GatewayClass
	Gateway      gatewayv1beta1.Gateway
	HTTPRoutes   []gatewayv1beta1.HTTPRoute
}

// GatewayAPI translates Gateway API resources into a model.
// The current implementation only supports HTTPRoute.
// TODO(tam): Support GatewayClass
func GatewayAPI(input Input) []model.HTTPListener {
	var res []model.HTTPListener

	for _, l := range input.Gateway.Spec.Listeners {
		if l.Protocol != gatewayv1beta1.HTTPProtocolType && l.Protocol != gatewayv1beta1.HTTPSProtocolType {
			continue
		}

		hostName := "*"
		if l.Hostname != nil {
			hostName = string(*l.Hostname)
		}
		var routes []model.HTTPRoute

		for _, r := range input.HTTPRoutes {
			matchedHostName := false
			for _, h := range r.Spec.Hostnames {
				// TODO(tam): Support wildcard matching as per gateway API spec
				if hostName == string(h) {
					matchedHostName = true
					break
				}
			}

			if !matchedHostName && hostName != "*" {
				break
			}

			for _, rule := range r.Spec.Rules {
				bes := make([]model.Backend, 0, len(rule.BackendRefs))
				for _, be := range rule.BackendRefs {
					bes = append(bes, toBackend(be, r.Namespace))
				}
				for _, match := range rule.Matches {
					// TODO(tam): Support more matching type such as Headers, QueryParams, etc.
					if match.Path != nil && match.Path.Type != nil {
						switch *match.Path.Type {
						case gatewayv1beta1.PathMatchExact:
							routes = append(routes, model.HTTPRoute{
								PathMatch: model.StringMatch{
									Exact: *match.Path.Value,
								},
								Backends: bes,
							})
						case gatewayv1beta1.PathMatchPathPrefix:
							routes = append(routes, model.HTTPRoute{
								PathMatch: model.StringMatch{
									Prefix: *match.Path.Value,
								},
								Backends: bes,
							})
						case gatewayv1beta1.PathMatchRegularExpression:
							routes = append(routes, model.HTTPRoute{
								PathMatch: model.StringMatch{
									Regex: *match.Path.Value,
								},
								Backends: bes,
							})
						}
					}

				}
			}
		}

		res = append(res, model.HTTPListener{
			Name: string(l.Name),
			Sources: []model.FullyQualifiedResource{
				{
					Name:      input.Gateway.GetName(),
					Namespace: input.Gateway.GetNamespace(),
					Group:     input.Gateway.GroupVersionKind().Group,
					Version:   input.Gateway.GroupVersionKind().Version,
					Kind:      input.Gateway.GroupVersionKind().Kind,
					UID:       string(input.Gateway.GetUID()),
				},
			},
			Port:     uint32(l.Port),
			Hostname: hostName,
			// TODO(tam): Support TLS
			TLS:    nil,
			Routes: routes,
		})
	}

	return res
}

func toBackend(be gatewayv1beta1.HTTPBackendRef, defaultNamespace string) model.Backend {
	ns := namespaceDerefOr(be.Namespace, defaultNamespace)
	var port *model.BackendPort

	if be.Port != nil {
		port = &model.BackendPort{
			Port: uint32(*be.Port),
		}
	}
	return model.Backend{
		Name:      string(be.Name),
		Namespace: ns,
		Port:      port,
	}
}

func namespaceDerefOr(namespace *gatewayv1beta1.Namespace, defaultNamespace string) string {
	if namespace != nil && *namespace != "" {
		return string(*namespace)
	}
	return defaultNamespace
}

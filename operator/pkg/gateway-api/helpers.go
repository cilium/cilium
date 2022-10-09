// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

const (
	allHosts = "*"

	kindGateway   = "Gateway"
	kindHTTPRoute = "HTTPRoute"
	kindService   = "Service"
)

func GatewayAddressTypePtr(addr gatewayv1beta1.AddressType) *gatewayv1beta1.AddressType {
	return &addr
}

func GroupPtr(name string) *gatewayv1beta1.Group {
	group := gatewayv1beta1.Group(name)
	return &group
}

func namespaceDerefOr(namespace *gatewayv1beta1.Namespace, defaultNamespace string) string {
	if namespace != nil && *namespace != "" {
		return string(*namespace)
	}
	return defaultNamespace
}

// isAttachable returns true if the provided HTTPRoute is attachable to given gateway
func isAttachable(ctx context.Context, c client.Client, gw *gatewayv1beta1.Gateway, hr *gatewayv1beta1.HTTPRoute) bool {
	for _, listener := range gw.Spec.Listeners {
		if listener.Protocol != gatewayv1beta1.HTTPProtocolType &&
			listener.Protocol != gatewayv1beta1.HTTPSProtocolType {
			continue
		}

		allowed := false
		if listener.AllowedRoutes != nil {
			if listener.AllowedRoutes.Kinds != nil {
				for _, kind := range listener.AllowedRoutes.Kinds {
					if (kind.Group == nil || string(*kind.Group) != "gateway.networking.k8s.io") &&
						kind.Kind != kindHTTPRoute {
						return false
					}
				}
			}

			if listener.AllowedRoutes.Namespaces != nil {
				switch *listener.AllowedRoutes.Namespaces.From {
				case gatewayv1beta1.NamespacesFromAll:
					allowed = true
				case gatewayv1beta1.NamespacesFromSame:
					allowed = hr.GetNamespace() == gw.GetNamespace()
				case gatewayv1beta1.NamespacesFromSelector:
					nsList := &slim_corev1.NamespaceList{}
					selector, _ := metav1.LabelSelectorAsSelector(listener.AllowedRoutes.Namespaces.Selector)
					if err := c.List(ctx, nsList, client.MatchingLabelsSelector{
						Selector: selector,
					}); err == nil {
						for _, ns := range nsList.Items {
							if ns.Name == hr.GetNamespace() {
								allowed = true
								break
							}
						}
					}
				default:
				}
			}
		}

		if !allowed {
			return false
		}

		hosts := computeHosts(hr.Spec.Hostnames, listener.Hostname)
		if len(hosts) == 0 {
			return false
		}
	}
	return true
}

// computeHosts returns a list of the intersecting hostnames between the route and the listener.
// The below function is inspired from https://github.com/envoyproxy/gateway/blob/main/internal/gatewayapi/helpers.go.
// Special thanks to Envoy team.
func computeHosts(routeHostnames []gatewayv1beta1.Hostname, listenerHostname *gatewayv1beta1.Hostname) []string {
	var listenerHostnameVal string
	if listenerHostname != nil {
		listenerHostnameVal = string(*listenerHostname)
	}

	// No route hostnames specified: use the listener hostname if specified,
	// or else match all hostnames.
	if len(routeHostnames) == 0 {
		if len(listenerHostnameVal) > 0 {
			return []string{listenerHostnameVal}
		}

		return []string{allHosts}
	}

	var hostnames []string

	for i := range routeHostnames {
		routeHostname := string(routeHostnames[i])

		switch {
		// No listener hostname: use the route hostname.
		case len(listenerHostnameVal) == 0:
			hostnames = append(hostnames, routeHostname)

		// Listener hostname matches the route hostname: use it.
		case listenerHostnameVal == routeHostname:
			hostnames = append(hostnames, routeHostname)

		// Listener has a wildcard hostname: check if the route hostname matches.
		case strings.HasPrefix(listenerHostnameVal, allHosts):
			if hostnameMatchesWildcardHostname(routeHostname, listenerHostnameVal) {
				hostnames = append(hostnames, routeHostname)
			}

		// Route has a wildcard hostname: check if the listener hostname matches.
		case strings.HasPrefix(routeHostname, allHosts):
			if hostnameMatchesWildcardHostname(listenerHostnameVal, routeHostname) {
				hostnames = append(hostnames, listenerHostnameVal)
			}
		}
	}

	return hostnames
}

// hostnameMatchesWildcardHostname returns true if hostname has the non-wildcard
// portion of wildcardHostname as a suffix, plus at least one DNS label matching the
// wildcard.
func hostnameMatchesWildcardHostname(hostname, wildcardHostname string) bool {
	if !strings.HasSuffix(hostname, strings.TrimPrefix(wildcardHostname, allHosts)) {
		return false
	}

	wildcardMatch := strings.TrimSuffix(hostname, strings.TrimPrefix(wildcardHostname, allHosts))
	return len(wildcardMatch) > 0
}

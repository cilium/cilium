// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"log/slog"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const allHosts = "*"

func GatewayHasMatchingControllerFn(ctx context.Context, c client.Client, controllerName string, logger *slog.Logger) func(object client.Object) bool {
	return func(obj client.Object) bool {
		scopedLog := logger.With(
			logfields.Resource, obj.GetName(),
		)
		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return false
		}

		gwc := &gatewayv1.GatewayClass{}
		key := types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}
		if err := c.Get(ctx, key, gwc); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to get GatewayClass", logfields.Error, err)
			return false
		}

		return string(gwc.Spec.ControllerName) == controllerName
	}
}

// IsHTTPSTerminatedListener returns true for HTTPS listeners that terminate TLS.
func IsHTTPSTerminatedListener(listener *gatewayv1.Listener) bool {
	return listener.Protocol == gatewayv1.HTTPSProtocolType
}

// IsTLSPassthroughListener returns true for TLS listeners configured for passthrough mode.
func IsTLSPassthroughListener(listener *gatewayv1.Listener) bool {
	return listener.Protocol == gatewayv1.TLSProtocolType &&
		listener.TLS != nil &&
		listener.TLS.Mode != nil &&
		*listener.TLS.Mode == gatewayv1.TLSModePassthrough
}

// ListenerHostname returns the listener hostname, or an empty string for catch-all listeners.
func ListenerHostname(listener *gatewayv1.Listener) string {
	if listener.Hostname == nil {
		return ""
	}
	return string(*listener.Hostname)
}

// SNIHostnamesIntersect returns true when two hostnames can match the same
// SNI value. Empty hostnames are normalized to catch-all.
func SNIHostnamesIntersect(a, b string) bool {
	a = normalizeHostname(a)
	b = normalizeHostname(b)

	if a == allHosts || b == allHosts {
		return true
	}
	if a == b {
		return true
	}

	aWildcard := strings.HasPrefix(a, allHosts)
	bWildcard := strings.HasPrefix(b, allHosts)

	switch {
	case aWildcard && bWildcard:
		return wildcardHostnamesIntersect(a, b)
	case aWildcard:
		return hostnameMatchesWildcardHostname(b, a)
	case bWildcard:
		return hostnameMatchesWildcardHostname(a, b)
	default:
		return false
	}
}

func normalizeHostname(hostname string) string {
	if hostname == "" {
		return allHosts
	}
	return hostname
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

func wildcardHostnamesIntersect(routeHostname, listenerHostname string) bool {
	if routeHostname == allHosts || listenerHostname == allHosts {
		return true
	}

	cutRouteHostname, found := strings.CutPrefix(routeHostname, "*.")
	if !found || len(cutRouteHostname) == 0 {
		return false
	}
	cutListenerHostname, found := strings.CutPrefix(listenerHostname, "*.")
	if !found || len(cutListenerHostname) == 0 {
		return false
	}

	routeSlice := strings.Split(routeHostname, ".")
	listenerSlice := strings.Split(listenerHostname, ".")
	slices.Reverse(routeSlice)
	slices.Reverse(listenerSlice)

	if len(routeSlice) == 0 || len(listenerSlice) == 0 {
		return false
	}

	maxLength := max(len(routeSlice), len(listenerSlice))
	matchingLabels := 0
	for i := range maxLength {
		if routeSlice[i] == allHosts || listenerSlice[i] == allHosts {
			break
		}
		if routeSlice[i] == listenerSlice[i] {
			matchingLabels++
		} else {
			return false
		}
	}
	return matchingLabels > 0
}

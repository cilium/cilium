// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"slices"
	"strings"
)

const allHosts = "*"

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

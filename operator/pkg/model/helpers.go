// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"slices"
	"strings"

	"github.com/google/go-cmp/cmp"
)

const (
	allHosts = "*"
)

func AddSource(sourceList []FullyQualifiedResource, source FullyQualifiedResource) []FullyQualifiedResource {
	for _, s := range sourceList {
		if cmp.Equal(s, source) {
			return sourceList
		}
	}
	return append(sourceList, source)
}

// ComputeHosts returns a list of the intersecting hostnames between the route and the listener.
// The below function is inspired from https://github.com/envoyproxy/gateway/blob/main/internal/gatewayapi/helpers.go.
// Special thanks to Envoy team.
// The function takes a list of route hostnames, a listener hostname, and a list of other listener hostnames.
// Note that the listenerHostname value will be skipped if it is present in the otherListenerHosts list.
func ComputeHosts(routeHostnames []string, listenerHostname *string, otherListenerHosts []string) []string {
	var listenerHostnameVal string
	if listenerHostname != nil {
		listenerHostnameVal = *listenerHostname
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
		routeHostname := routeHostnames[i]

		switch {
		// No listener hostname: use the route hostname if there is no overlapping with other listener hostnames.
		case len(listenerHostnameVal) == 0:
			if !checkHostNameIsolation(routeHostname, listenerHostnameVal, otherListenerHosts) {
				hostnames = append(hostnames, routeHostname)
			}

		// Listener hostname matches the route hostname: use it.
		case listenerHostnameVal == routeHostname:
			hostnames = append(hostnames, routeHostname)

		case strings.HasPrefix(listenerHostnameVal, allHosts) &&
			strings.HasPrefix(routeHostname, allHosts) &&
			wildcardHostnamesIntersect(routeHostname, listenerHostnameVal) &&
			!checkHostNameIsolation(routeHostname, listenerHostnameVal, otherListenerHosts):

			// In this case, we need to append whichever hostname has more dns labels.
			splitRouteHostname := strings.Split(routeHostname, ".")
			splitListenerHostname := strings.Split(*listenerHostname, ".")
			if len(splitListenerHostname) > len(splitRouteHostname) {
				hostnames = append(hostnames, *listenerHostname)
			} else {
				hostnames = append(hostnames, routeHostname)
			}

		// Listener has a wildcard hostname: check if the route hostname matches.
		case strings.HasPrefix(listenerHostnameVal, allHosts):
			if hostnameMatchesWildcardHostname(routeHostname, listenerHostnameVal) &&
				!checkHostNameIsolation(routeHostname, listenerHostnameVal, otherListenerHosts) {
				hostnames = append(hostnames, routeHostname)
			}

		// Route has a wildcard hostname: check if the listener hostname matches.
		case strings.HasPrefix(routeHostname, allHosts):
			if hostnameMatchesWildcardHostname(listenerHostnameVal, routeHostname) {
				hostnames = append(hostnames, listenerHostnameVal)
			}
		}
	}

	slices.SortStableFunc(hostnames, sortHostnamesByWildcards)
	return hostnames
}

func sortHostnamesByWildcards(a, b string) int {
	if a == b {
		return 0
	}

	aOnlyWildcard := a == "*"
	bOnlyWildcard := b == "*"

	if aOnlyWildcard {
		// A is "*", B is not.
		// A is less than B (global wildcard greater than anything)
		return 1
	}

	if bOnlyWildcard {
		// B is "*", A is not.
		// A is greater than B (global wildcard greater than anything)
		return -1
	}

	//
	aLabels := strings.Split(a, ".")
	bLabels := strings.Split(b, ".")

	if len(aLabels) < len(bLabels) {
		// B is longer.
		if bLabels[0] == "*" && aLabels[0] != "*" {
			// If the first element of B is a wildcard, and A is not,
			// then B is _less_ specific, so A is first.
			return -1
		}
		return 1
	}

	if len(aLabels) > len(bLabels) {
		// A is longer.
		if aLabels[0] == "*" && bLabels[0] != "*" {
			// If the first element of A is a wildcard, and B is not,
			// then A is _less_ specific, so B is first.
			return 1
		}
		return -1
	}

	// Trim the wildcards, then compare lengths again.
	if aLabels[0] == "*" {
		aLabels = slices.Delete(aLabels, 0, 1)
	}

	if bLabels[0] == "*" {
		bLabels = slices.Delete(bLabels, 0, 1)
	}

	if len(aLabels) < len(bLabels) {
		return 1
	}

	if len(aLabels) > len(bLabels) {
		return -1
	}

	// Either both had wildcards did, or neither.
	// In either case we lexically sort the strings.
	return strings.Compare(a, b)
}

func checkHostNameIsolation(routeHostname string, listenerHostName string, excludedListenerHostnames []string) bool {
	for _, exHost := range excludedListenerHostnames {
		if exHost == listenerHostName {
			continue
		}
		if routeHostname == exHost {
			return true
		}
		if strings.HasPrefix(exHost, allHosts) &&
			hostnameMatchesWildcardHostname(routeHostname, exHost) &&
			len(exHost) > len(listenerHostName) {
			return true
		}
	}

	return false
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
	// Check for global wildcards.
	matchAnyRoute := false
	if routeHostname == "*" {
		matchAnyRoute = true
	}
	matchAnyListener := false
	if listenerHostname == "*" {
		matchAnyListener = true
	}

	if matchAnyRoute || matchAnyListener {
		return true
	}

	// Check wildcards are properly formed (that is, that they have at least one other label)
	cutRouteHostname, found := strings.CutPrefix(routeHostname, "*.")
	if !found {
		// One of the hostnames is incorrectly formed, this shouldn't happen, but return false anyway
		return false
	}
	if len(cutRouteHostname) == 0 {
		// Malformed wildcard
		return false
	}
	// Check wildcards are properly formed (that is, that they have at least one other label)
	cutListenerHostname, found := strings.CutPrefix(listenerHostname, "*.")
	if !found {
		// One of the hostnames is incorrectly formed, this shouldn't happen, but return false anyway
		return false
	}
	if len(cutListenerHostname) == 0 {
		// Malformed wildcard
		return false
	}

	// reversing the slices lets us traverse them right-to-left.
	routeSlice := strings.Split(routeHostname, ".")
	listenerSlice := strings.Split(listenerHostname, ".")
	slices.Reverse(routeSlice)
	slices.Reverse(listenerSlice)

	if len(routeSlice) == 0 || len(listenerSlice) == 0 {
		return false
	}

	maxLength := max(len(routeSlice), len(listenerSlice))

	matchingLabels := 0

	for i := 0; i < maxLength; i++ {
		if routeSlice[i] == "*" || listenerSlice[i] == "*" {
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

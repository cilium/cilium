// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"crypto/sha256"
	"fmt"
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

	slices.Sort(hostnames)
	return hostnames
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

// Shorten shortens the string to 63 characters.
// this is the implicit required for all the resource naming in k8s.
func Shorten(s string) string {
	if len(s) > 63 {
		return s[:52] + "-" + encodeHash(hash(s))
	}
	return s
}

// encodeHash encodes the first 10 characters of the hex string.
// https://github.com/kubernetes/kubernetes/blob/f0dcf0614036d8c3cd1c9f3b3cf8df4bb1d8e44e/staging/src/k8s.io/kubectl/pkg/util/hash/hash.go#L105
func encodeHash(hex string) string {
	enc := []rune(hex[:10])
	for i := range enc {
		switch enc[i] {
		case '0':
			enc[i] = 'g'
		case '1':
			enc[i] = 'h'
		case '3':
			enc[i] = 'k'
		case 'a':
			enc[i] = 'm'
		case 'e':
			enc[i] = 't'
		}
	}
	return string(enc)
}

// hash hashes `data` with sha256 and returns the hex string
func hash(data string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}

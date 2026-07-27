// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"regexp"
	"strings"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	ciliumBPFMetadataListenerFilterName = "cilium.bpf_metadata"
)

var (
	// subdomainWildcardSpecifierPrefix is the regular expression to match subdomain wildcard prefix
	// in match patterns. This regex will match '**.', '****.' and so on.
	// These prefixes are special case which allows matching multilevel subdomains.
	subdomainWildcardSpecifierPrefixRE = regexp.MustCompile(`^[*]{2,}[.]`)

	// subdomain wildcard specifier prefix which envoy expects.
	subdomainWildcardSpecifierPrefix = "**."

	// wildcardSpecifier is the regular expression used to reduce wildcards in match pattern.
	wildcardSpecifierRE = regexp.MustCompile("[*]{2,}")
)

// cilium-agent SNI match pattern exposes the same sematics as FQDN match patterns to users.
// However, this is not mapped 1:1 with cilium-envoy match pattern semantics.
// This method converts the provided match pattern from cilium-agent representation to a
// pattern that envoy understands. More details: https://github.com/cilium/proxy/pull/1698
//
// The following transformations are performed on the pattern:
//
// - Drop trailing dot('.') if present.
//
// - Compress subdomain wildcard specifier prefix: `^[*]{2,}[.]` -> `**.`
//   - cilium-agent allows users to specify multiple wildcard characters('*') as part of
//     a subdomain wildcard specifier prefix. For example all `**.`, `***.`, `****.`, etc
//     prefix results in the same semantic of allowing all multilevel subdomains in prefix.
//     To make this compatible with envoy match pattern syntax all such specifiers are
//     reduced to `**.`
//
// - Compress other wildcard specifiers in match pattern: `[*]{2,}` -> `*`
//   - Similar to subdomain wildcard specifier prefix, cilium-agent allows wildcard('*') to
//     be specified multiple times which has the same semantic to that of a single wildcard('*').
func sanitizeServerNamePattern(pattern string) string {
	// Drop trailing dot if present.
	pattern = strings.TrimSuffix(pattern, ".")

	// Reduce redundant wildcard characters from match pattern prefix.
	hasSubdomainWildcardSpecifierPrefix := false
	if subdomainWildcardSpecifierPrefixRE.MatchString(pattern) {
		hasSubdomainWildcardSpecifierPrefix = true
		pattern = subdomainWildcardSpecifierPrefixRE.ReplaceAllString(pattern, "")
	}

	// Reduce all redundant wildcards in the pattern: **, ***, **** -> *
	pattern = wildcardSpecifierRE.ReplaceAllString(pattern, "*")
	if hasSubdomainWildcardSpecifierPrefix {
		return subdomainWildcardSpecifierPrefix + pattern
	}
	return pattern
}

// listenerRequiresNPDS returns true if the listener carries a cilium.bpf_metadata
// listener filter that will start an NPDS (Network Policy Discovery Service) client.
//
// For the listener to start the NPDS client it must have a correctly configured
// bpf_root (matching the system's BPF filesystem root)
//
// Corresponding proxy logic: https://github.com/cilium/proxy/blob/4054ac22c6338f0372aac9f23a7cda99e8ebf6da/cilium/bpf_metadata.cc#L273
func listenerRequiresNPDS(listener *envoy_config_listener.Listener) bool {
	for _, lf := range listener.GetListenerFilters() {
		if lf.GetName() != ciliumBPFMetadataListenerFilterName || lf.GetTypedConfig() == nil {
			continue
		}

		var bpfMeta cilium.BpfMetadata
		err := lf.GetTypedConfig().UnmarshalTo(&bpfMeta)

		if err == nil && bpfMeta.GetBpfRoot() == bpf.BPFFSRoot() {
			return true
		}
	}
	return false
}

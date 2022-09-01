// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"fmt"
	"strings"
)

const (
	slash       = "/"
	dot         = "."
	starDot     = "*."
	dotRegex    = "[.]"
	notDotRegex = "[^.]"
)

// getMatchingPrefixRegex returns safe regex used by envoy to match the prefix.
// By default, prefix matching in envoy will not reject /foobar if the original path is only /foo. Hence, conversion
// with safe regex is required.
//
// If the original path is /foo, the returned regex will be /foo(/.*)?$
// - /foo -> matched
// - /foo/ -> matched
// - /foobar -> not matched
func getMatchingPrefixRegex(path string) string {
	removedTrailingSlash := path
	if strings.HasSuffix(path, slash) {
		removedTrailingSlash = removedTrailingSlash[:len(removedTrailingSlash)-1]
	}
	return fmt.Sprintf("%s(/.*)?$", removedTrailingSlash)
}

// getMatchingHeaderRegex is to make sure that one and only one single subdomain is matched e.g.
// For example, *.foo.com should only match bar.foo.com but not baz.bar.foo.com
func getMatchingHeaderRegex(host string) string {
	if strings.HasPrefix(host, starDot) {
		return fmt.Sprintf("^%s+%s%s$", notDotRegex, dotRegex, strings.ReplaceAll(host[2:], dot, dotRegex))
	}
	return fmt.Sprintf("^%s$", strings.ReplaceAll(host, dot, dotRegex))
}

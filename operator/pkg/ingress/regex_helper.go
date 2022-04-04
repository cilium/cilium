// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"fmt"
	"strings"
)

const slash = "/"

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

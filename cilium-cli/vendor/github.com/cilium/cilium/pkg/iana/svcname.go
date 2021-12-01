// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package iana

import (
	"regexp"
)

// IANA Service Name consists of alphanumeric characters of which at
// least one is not a number, as well as non-consecutive dashes ('-')
// except for in the beginning or the end.
// Note: Character case must be ignored when comparing service names.
var isSvcName = regexp.MustCompile(`^([a-zA-Z0-9]-?)*[a-zA-Z](-?[a-zA-Z0-9])*$`).MatchString

// IsSvcName returns true if the string conforms to IANA Service Name specification
// (RFC 6335 Section 5.1. Service Name Syntax)
func IsSvcName(name string) bool {
	return len(name) > 0 && len(name) <= 15 && isSvcName(name)
}

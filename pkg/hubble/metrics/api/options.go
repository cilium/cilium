// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"strings"
)

// Options are options provided to a metric handler
type Options map[string]string

// ParseOptions parses a metric handler option string into a options map
func ParseOptions(s string) (options Options) {
	options = Options{}

	for _, option := range strings.Split(s, ";") {
		if option == "" {
			continue
		}

		kv := strings.SplitN(option, "=", 2)
		if len(kv) == 2 {
			options[kv[0]] = kv[1]
		} else {
			options[kv[0]] = ""
		}
	}

	return
}

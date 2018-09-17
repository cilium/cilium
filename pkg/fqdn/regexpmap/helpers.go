// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package regexpmap

import (
	"regexp"
	"strings"
)

// simpleFQDNCheck matches plain DNS names
// See https://en.wikipedia.org/wiki/Hostname
var simpleFQDNCheck = regexp.MustCompile("[-a-zA-Z0-9.]*[.]$")

// IsSimpleFQDN checks if re has only letters and dots
func IsSimpleFQDN(re string) bool {
	return simpleFQDNCheck.MatchString(re)
}

// EscapeSimpleFQDN escapes the dots in simple DNS names to avoid spurious
// matches.
func EscapeSimpleFQDN(re string) string {
	if IsSimpleFQDN(re) {
		return strings.Replace(re, ".", "[.]", -1)
	}
	return re
}

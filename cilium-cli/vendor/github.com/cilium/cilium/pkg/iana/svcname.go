// Copyright 2020 Authors of Cilium
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

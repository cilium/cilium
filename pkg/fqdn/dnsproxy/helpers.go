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

package dnsproxy

import (
	"strings"

	"github.com/cilium/dns"
)

// prepareNameMatch ensures that a name is an anchored regexp and that names
// with only "." (aka not a regexp) escape the "." so it does not match any
// character. DNS expects lowercase lookups (ignoring the highest ascii bit)
// and we mimic this by lowercasing the name here, and lookups later.
// Note: The trailing "." in a FQDN is assumed, and isn't added here.
func prepareNameMatch(name string) string {
	name = strings.ToLower(name) // lowercase it

	// anchor it
	out := make([]string, 0, 3)
	if !strings.HasPrefix(name, "^") {
		out = append(out, "^")
	}
	out = append(out, name)
	if !strings.HasSuffix(name, "$") {
		out = append(out, "$")
	}
	return strings.Join(out, "")
}

// lookupTargetDNSServer finds the intended DNS target server for a specific
// request (passed in via ServeDNS) in proxymap. The IP:port combination is
// returned.
func lookupTargetDNSServer(w dns.ResponseWriter) (server string, err error) {
	return w.LocalAddr().String(), nil
}

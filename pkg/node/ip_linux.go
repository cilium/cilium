// Copyright 2017-2019 Authors of Cilium
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

package node

import (
	"strings"

	"github.com/vishvananda/netlink"
)

func init() {
	initExcludedIPs()
}

func initExcludedIPs() {
	// We exclude below bad device prefixes from address selection ...
	prefixes := []string{
		"docker",
	}
	links, err := netlink.LinkList()
	if err != nil {
		return
	}
	for _, l := range links {
		// ... also all down devices since they won't be reachable.
		//
		// We need to check for both "up" and "unknown" state, as some
		// drivers may not implement operstate handling, and just report
		// their state as unknown even though they are operational.
		if l.Attrs().OperState == netlink.OperUp ||
			l.Attrs().OperState == netlink.OperUnknown {
			skip := true
			for _, p := range prefixes {
				if strings.HasPrefix(l.Attrs().Name, p) {
					skip = false
					break
				}
			}
			if skip {
				continue
			}
		}
		addr, err := netlink.AddrList(l, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, a := range addr {
			excludedIPs = append(excludedIPs, a.IP)
		}
	}
}

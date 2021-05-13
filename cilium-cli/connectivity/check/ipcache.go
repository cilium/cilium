// Copyright 2020-2021 Authors of Cilium
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

package check

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ipCache is used to unmarshal the output of `cilium bpf ipcache list -o json` into.
// The value is a list of strings because the output is as follows:
// {
//   "10.0.0.13/32": [
//     "1 0 0.0.0.0"
//   ],
type ipCache map[string][]string

// findPodID checks the ipCache for the presence of the given Pod's IP address.
func (ic ipCache) findPodID(p Pod) (int, error) {
	podIP := p.Pod.Status.PodIP
	ip := net.ParseIP(podIP)
	if ip.To4() == nil && ip.To16() == nil {
		return 0, fmt.Errorf("PodIP %s is not a valid IPv4 or IPv6", podIP)
	}

	// We assume these prefixes, but this might not be true forever or
	// on all deployments.
	mask := "/32"
	if ip.To4() == nil {
		mask = "/128"
	}

	if v, ok := ic[ip.String()+mask]; ok {
		// Take the first-available ID, split "1 0 0.0.0.0" on each space.
		values := strings.Fields(v[0])
		if len(values) > 1 {
			if id, err := strconv.Atoi(values[0]); err == nil {
				// 0-255 is reserved for other identities, not Pods.
				if id < 256 {
					return 0, fmt.Errorf("ipcache ID %d is not a valid Pod ID", id)
				}

				return id, nil
			}
		}

		return 0, fmt.Errorf("error parsing Cilium ipcache entry '%s'", v[0])
	}

	return 0, fmt.Errorf("no ipcache entry found for Pod IP %s", ip)
}

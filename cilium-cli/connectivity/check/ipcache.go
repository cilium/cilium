// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ipCache is used to unmarshal the output of `cilium bpf ipcache list -o json` into.
// The value is a list of strings because the output is as follows:
//
//	{
//	  "10.0.0.13/32": [
//	    "1 0 0.0.0.0"
//	  ],
//	  ...
//	}
type ipCache map[string][]string

// findPodID checks the ipCache for the presence of the given Pod's IP addresses.
func (ic ipCache) findPodID(p Pod) (int, error) {
	var epID int
	for _, ip := range p.Pod.Status.PodIPs {
		id, err := ic._findPodID(ip.IP)
		if err != nil {
			return 0, err
		}
		if epID == 0 {
			epID = id
		} else if epID != id {
			return 0, fmt.Errorf("pod ID mismatch %d vs %d", epID, id)
		}
	}
	return epID, nil
}

func (ic ipCache) _findPodID(podIP string) (int, error) {
	ip, err := netip.ParseAddr(podIP)
	if err != nil {
		return 0, fmt.Errorf("PodIP %s is not a valid IPv4 or IPv6: %w", podIP, err)
	}

	// We assume these prefixes, but this might not be true forever or
	// on all deployments.
	mask := "/32"
	if ip.Is6() {
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

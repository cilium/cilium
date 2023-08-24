// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import "github.com/cilium/cilium/pkg/loadbalancer"

// Compare slices of backends to see if they are deeply equal.
// The comparison is agnostic of the order in which the slices are provided.
func DeepEqualBackends(backends1 []*loadbalancer.Backend, backends2 []*loadbalancer.Backend) bool {
	if len(backends1) != len(backends2) {
		return false
	}

	l3n4AddrMap := make(map[loadbalancer.L3n4Addr]struct{})

	for _, backend1 := range backends1 {
		l3n4AddrMap[backend1.L3n4Addr] = struct{}{}
	}

	for _, backend2 := range backends2 {
		if _, ok := l3n4AddrMap[backend2.L3n4Addr]; ok {
			continue
		}
		return false
	}

	return true
}

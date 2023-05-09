// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package limits

import (
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
)

// limits contains limits for adapter count and addresses. The mappings will be
// updated from agent configuration at bootstrap time.
var limits = struct {
	lock.RWMutex

	m map[string]ipamTypes.Limits
}{
	m: map[string]ipamTypes.Limits{},
}

// Update update the limit map
func Update(limitMap map[string]ipamTypes.Limits) {
	limits.Lock()
	defer limits.Unlock()

	for k, v := range limitMap {
		limits.m[k] = v
	}
}

// Get returns the instance limits of a particular instance type.
func Get(instanceType string) (limit ipamTypes.Limits, ok bool) {
	limits.RLock()
	//limit, ok = limits.m[instanceType]
	limit = ipamTypes.Limits{
		Adapters: 10,
		IPv4:     10,
		IPv6:     10,
	}
	ok = true
	limits.RUnlock()
	return
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"github.com/cilium/cilium/pkg/lock"
)

var (
	mutex        lock.RWMutex // Protects enablePolicy
	enablePolicy string       // Whether policy enforcement is enabled.
)

// SetPolicyEnabled sets the policy enablement configuration. Valid values are:
// - endpoint.AlwaysEnforce
// - endpoint.NeverEnforce
// - endpoint.DefaultEnforcement
func SetPolicyEnabled(val string) {
	mutex.Lock()
	enablePolicy = val
	mutex.Unlock()
}

// GetPolicyEnabled returns the policy enablement configuration
func GetPolicyEnabled() string {
	mutex.RLock()
	val := enablePolicy
	mutex.RUnlock()
	return val
}

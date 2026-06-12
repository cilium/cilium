// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumio

import (
	"strconv"
	"strings"
)

// NamedPortsIdentityLabelNameForIndex returns the generated named-ports label
// key for the chunk at index. Index zero uses the base label key.
func NamedPortsIdentityLabelNameForIndex(index int) string {
	if index == 0 {
		return NamedPortsIdentityLabelName
	}
	return NamedPortsIdentityLabelName + "-" + strconv.Itoa(index)
}

// IsNamedPortsIdentityLabelName returns true if key is the base named-ports
// identity label key or one of its numbered continuation keys.
func IsNamedPortsIdentityLabelName(key string) bool {
	if key == NamedPortsIdentityLabelName {
		return true
	}
	suffix, ok := strings.CutPrefix(key, NamedPortsIdentityLabelName+"-")
	if !ok || suffix == "" {
		return false
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

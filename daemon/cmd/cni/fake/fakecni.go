// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

type FakeCNIConfigManager struct{}

func (f *FakeCNIConfigManager) GetMTU() int {
	return 0
}

// GetChainingMode returns the configured CNI chaining mode
func (f *FakeCNIConfigManager) GetChainingMode() string {
	return "none"
}

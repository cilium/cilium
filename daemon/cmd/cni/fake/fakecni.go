// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import "github.com/cilium/cilium/plugins/cilium-cni/types"

type FakeCNIConfigManager struct{}

func (f *FakeCNIConfigManager) GetMTU() int {
	return 0
}

// GetChainingMode returns the configured CNI chaining mode
func (f *FakeCNIConfigManager) GetChainingMode() string {
	return "none"
}

// GetNetConf returns the *NetConf obtained from CNI configuration file
func (f *FakeCNIConfigManager) GetNetConf() *types.NetConf {
	return nil
}

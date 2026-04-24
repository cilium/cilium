// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"github.com/cilium/cilium/api/v1/models"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

type FakeCNIConfigManager struct {
	MTU                 int
	ChainingMode        string
	ExternalRouting     bool
	CustomNetConf       *cnitypes.NetConf
	DelegatedIPAMCNIBinDir string
}

func (f *FakeCNIConfigManager) GetMTU() int {
	return f.MTU
}

// GetChainingMode returns the configured CNI chaining mode
func (f *FakeCNIConfigManager) GetChainingMode() string {
	if f.ChainingMode == "" {
		return "none"
	}
	return f.ChainingMode
}

func (f *FakeCNIConfigManager) ExternalRoutingEnabled() bool {
	return f.ExternalRouting
}

func (f *FakeCNIConfigManager) GetCustomNetConf() *cnitypes.NetConf {
	return f.CustomNetConf
}

func (f *FakeCNIConfigManager) Status() *models.Status {
	return nil
}

func (f *FakeCNIConfigManager) GetDelegatedIPAMCNIBinPath() string {
	return f.DelegatedIPAMCNIBinDir
}

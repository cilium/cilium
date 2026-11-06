// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"github.com/cilium/cilium/api/v1/models"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

// FakeCNIConfigManager is a no-op CNIConfigManager implementation for tests.
// Fields configure the values returned by the corresponding methods.
type FakeCNIConfigManager struct {
	MTU                     int
	ChainingMode            string
	ExternalRouting         bool
	CustomNetConf           *cnitypes.NetConf
	DelegatedIPAMCNIBinPath string
}

// GetMTU returns the configured MTU.
func (f *FakeCNIConfigManager) GetMTU() int {
	return f.MTU
}

// GetChainingMode returns the configured CNI chaining mode.
func (f *FakeCNIConfigManager) GetChainingMode() string {
	if f.ChainingMode == "" {
		return "none"
	}
	return f.ChainingMode
}

// ExternalRoutingEnabled returns the configured external-routing flag.
func (f *FakeCNIConfigManager) ExternalRoutingEnabled() bool {
	return f.ExternalRouting
}

// GetCustomNetConf returns the configured custom NetConf, if any.
func (f *FakeCNIConfigManager) GetCustomNetConf() *cnitypes.NetConf {
	return f.CustomNetConf
}

// Status always returns nil.
func (f *FakeCNIConfigManager) Status() *models.Status {
	return nil
}

// GetDelegatedIPAMCNIBinPath returns the configured CNI bin directory used for delegated IPAM.
func (f *FakeCNIConfigManager) GetDelegatedIPAMCNIBinPath() string {
	return f.DelegatedIPAMCNIBinPath
}

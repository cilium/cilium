// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

var _ datapath.IptablesManager = (*FakeIptablesManager)(nil)

type FakeIptablesManager struct {
}

// NewIptablesManager returns a new fake IptablesManager
func NewIptablesManager() *FakeIptablesManager {
	return &FakeIptablesManager{}
}

func (f *FakeIptablesManager) InstallProxyRules(uint16, string) {
}

func (f *FakeIptablesManager) SupportsOriginalSourceAddr() bool {
	return false
}

func (m *FakeIptablesManager) GetProxyPorts() map[string]uint16 {
	return nil
}

func (m *FakeIptablesManager) InstallNoTrackRules(ip netip.Addr, port uint16) {
}

func (m *FakeIptablesManager) RemoveNoTrackRules(ip netip.Addr, port uint16) {
}

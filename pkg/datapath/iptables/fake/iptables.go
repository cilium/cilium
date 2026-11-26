// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"iter"
	"maps"
	"net/netip"

	"github.com/cilium/cilium/pkg/datapath/iptables"
)

var _ iptables.Manager = (*Manager)(nil)

type Manager struct {
}

// NewManager returns a new fake IptablesManager
func NewManager() *Manager {
	return &Manager{}
}

func (f *Manager) InstallProxyRules(uint16, string) {
}

func (f *Manager) SupportsOriginalSourceAddr() bool {
	return false
}

func (m *Manager) RestoredProxyPorts() iter.Seq2[string, uint16] {
	return maps.All(map[string]uint16(nil))
}

func (m *Manager) RestoredProxyPort(string) uint16 {
	return 0
}

func (m *Manager) InstallNoTrackRules(ip netip.Addr, port uint16) {
}

func (m *Manager) RemoveNoTrackRules(ip netip.Addr, port uint16) {
}

func (m *Manager) AddNoTrackHostPorts(namespace, name string, ports []string) {
}

func (m *Manager) RemoveNoTrackHostPorts(namespace, name string) {
}

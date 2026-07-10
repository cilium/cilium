// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import "github.com/cilium/cilium/pkg/datapath/linux/bandwidth"

var _ bandwidth.Manager = (*Manager)(nil)

type Manager struct{}

func (fbm *Manager) DeleteBandwidthLimit(endpointID uint16) {
}

func (fbm *Manager) UpdateBandwidthLimit(endpointID uint16, bytesPerSecond uint64, prio uint32) {
}

func (fbm *Manager) UpdateIngressBandwidthLimit(endpointID uint16, bytesPerSecond uint64) {}

func (fbm *Manager) DeleteIngressBandwidthLimit(endpointID uint16) {}

func (fbm *Manager) BBREnabled() bool {
	return false
}
func (fbm *Manager) DeleteEndpointBandwidthLimit(epID uint16) error {
	return nil
}
func (fbm *Manager) Enabled() bool {
	return false
}
func (fbm *Manager) ResetQueues() bool {
	return false
}

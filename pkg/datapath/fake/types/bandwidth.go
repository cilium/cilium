// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "github.com/cilium/cilium/pkg/datapath/types"

var _ types.BandwidthManager = (*BandwidthManager)(nil)

type BandwidthManager struct{}

func (fbm *BandwidthManager) DeleteBandwidthLimit(endpointID uint16) {
}

func (fbm *BandwidthManager) UpdateBandwidthLimit(endpointID uint16, bytesPerSecond uint64, prio uint32) {
}

func (fbm *BandwidthManager) UpdateIngressBandwidthLimit(endpointID uint16, bytesPerSecond uint64) {}

func (fbm *BandwidthManager) DeleteIngressBandwidthLimit(endpointID uint16) {}

func (fbm *BandwidthManager) BBREnabled() bool {
	return false
}
func (fbm *BandwidthManager) DeleteEndpointBandwidthLimit(epID uint16) error {
	return nil
}
func (fbm *BandwidthManager) Enabled() bool {
	return false
}
func (fbm *BandwidthManager) ResetQueues() bool {
	return false
}

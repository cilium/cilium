// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import "github.com/cilium/cilium/pkg/datapath/types"

var _ types.BandwidthManager = (*BandwidthManager)(nil)

type BandwidthManager struct{}

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

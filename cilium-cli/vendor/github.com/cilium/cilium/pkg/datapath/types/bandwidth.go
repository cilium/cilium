// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

type BandwidthManager interface {
	BBREnabled() bool
	DeleteEndpointBandwidthLimit(epID uint16) error
	Enabled() bool
}

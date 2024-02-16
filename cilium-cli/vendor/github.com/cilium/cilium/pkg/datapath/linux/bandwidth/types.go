// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bandwidth

type Manager interface {
	BBREnabled() bool
	DeleteEndpointBandwidthLimit(epID uint16) error
	Enabled() bool
}

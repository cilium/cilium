// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// GNeighConfig contains the configuration for the GARP cell.
type GNeighConfig struct {
	EnableL2PodAnnouncements bool
}

func (def GNeighConfig) Enabled() bool {
	return def.EnableL2PodAnnouncements
}

type L2PodAnnouncementConfig interface {
	Enabled() bool
}

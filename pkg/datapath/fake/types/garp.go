// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// GarpConfig contains the configuration for the GARP cell.
type GarpConfig struct {
	EnableL2PodAnnouncements bool
}

func (def GarpConfig) Enabled() bool {
	return def.EnableL2PodAnnouncements
}

type L2PodAnnouncementConfig interface {
	Enabled() bool
}

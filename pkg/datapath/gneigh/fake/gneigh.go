// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

// Config contains the configuration for the GARP cell.
type Config struct {
	EnableL2PodAnnouncements bool
}

func (def Config) Enabled() bool {
	return def.EnableL2PodAnnouncements
}

type L2PodAnnouncementConfig interface {
	Enabled() bool
}

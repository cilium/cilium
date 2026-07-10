// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gneigh

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	L2PodAnnouncementsInterfacePattern = "l2-pod-announcements-interface-pattern"

	EnableL2PodAnnouncements = "enable-l2-pod-announcements"
)

// Config contains the configuration for the Gneigh cell.
type Config struct {
	L2PodAnnouncementsInterfacePattern string
	EnableL2PodAnnouncements           bool
}

func (def Config) Enabled() bool {
	return def.EnableL2PodAnnouncements
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(L2PodAnnouncementsInterfacePattern, def.L2PodAnnouncementsInterfacePattern, "Regex matching interfaces used for sending gratuitous ARP and NDP messages")
	flags.Bool(EnableL2PodAnnouncements, def.EnableL2PodAnnouncements, "Enable announcing Pod IPs with Gratuitous ARP and NDP")
}

// This cell can't be enabled by default, it's entirely env dependent.
var defaultConfig = Config{
	EnableL2PodAnnouncements:           false,
	L2PodAnnouncementsInterfacePattern: "",
}

// Cell processes k8s pod events for the local node and determines if a
// Gratuitous ARP|ND packet needs to be sent.
var Cell = cell.Module(
	"l2-pod-announcements-gneigh",
	"Gneigh processor sends gratuitous ARP and NDP packets for local pods",

	cell.Provide(
		newSender,
		func(c Config) L2PodAnnouncementConfig {
			return c
		}),

	cell.Config(defaultConfig),

	cell.Invoke(newGNeighProcessor),
)

type L2PodAnnouncementConfig interface {
	Enabled() bool
}

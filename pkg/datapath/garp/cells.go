// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package garp

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	// L2PodAnnouncementsInterface is the interface used to send Gratuitous ARP messages.
	L2PodAnnouncementsInterface = "l2-pod-announcements-interface"

	EnableL2PodAnnouncements = "enable-l2-pod-announcements"
)

// Config contains the configuration for the GARP cell.
type Config struct {
	L2PodAnnouncementsInterface string
	EnableL2PodAnnouncements    bool
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(L2PodAnnouncementsInterface, def.L2PodAnnouncementsInterface, "Interface used for sending gratuitous arp messages")
	flags.Bool(EnableL2PodAnnouncements, def.EnableL2PodAnnouncements, "Enable announcing Pod IPs with Gratuitous ARP")
}

// Cell processes k8s pod events for the local node and determines if a
// Gratuitous ARP packet needs to be sent.
var Cell = cell.Module(
	"l2-pod-announcements-garp",
	"GARP processor sends gratuitous ARP packets for local pods",

	cell.Provide(newGARPSender),

	// This cell can't have a default config, it's entirely env dependent.
	cell.Config(Config{}),

	cell.Invoke(newGARPProcessor),
)

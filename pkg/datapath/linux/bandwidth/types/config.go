// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "github.com/spf13/pflag"

const (
	EnableBandwidthManagerFlag = "enable-bandwidth-manager"
	EnableBBRFlag              = "enable-bbr"
	EnableBBRHostnsOnlyFlag    = "enable-bbr-hostns-only"
	EnableDSCPMarkingFlag      = "enable-dscp-marking"
)

type Config struct {
	// EnableBandwidthManager enables EDT-based pacing
	EnableBandwidthManager bool

	// EnableBBR enables BBR TCP congestion control for the node including Pods
	EnableBBR bool

	// EnableBBRHostnsOnly enables BBR TCP congestion control for the node excluding Pods
	EnableBBRHostnsOnly bool

	// EnableDSCPMarking enables DSCP marking for Pod egress traffic.
	EnableDSCPMarking bool
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableBandwidthManagerFlag, def.EnableBandwidthManager, "Enable BPF bandwidth manager")
	flags.Bool(EnableBBRFlag, def.EnableBBR, "Enable BBR for the bandwidth manager")
	flags.Bool(EnableBBRHostnsOnlyFlag, def.EnableBBRHostnsOnly, "Enable BBR only in the host network namespace.")
	flags.Bool(EnableDSCPMarkingFlag, def.EnableDSCPMarking, "Enable DSCP marking for Pod egress traffic")
}

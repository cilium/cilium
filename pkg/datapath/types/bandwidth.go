// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "github.com/spf13/pflag"

const (
	EnableBandwidthManagerFlag = "enable-bandwidth-manager"
	EnableBBRFlag              = "enable-bbr"
	EnableBBRHostnsOnlyFlag    = "enable-bbr-hostns-only"
)

type BandwidthConfig struct {
	// EnableBandwidthManager enables EDT-based pacing
	EnableBandwidthManager bool

	// EnableBBR enables BBR TCP congestion control for the node including Pods
	EnableBBR bool

	// EnableBBRHostnsOnly enables BBR TCP congestion control for the node excluding Pods
	EnableBBRHostnsOnly bool
}

func (def BandwidthConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableBandwidthManagerFlag, def.EnableBandwidthManager, "Enable BPF bandwidth manager")
	flags.Bool(EnableBBRFlag, def.EnableBBR, "Enable BBR for the bandwidth manager")
	flags.Bool(EnableBBRHostnsOnlyFlag, def.EnableBBRHostnsOnly, "Enable BBR only in the host network namespace.")
}

var DefaultBandwidthConfig = BandwidthConfig{
	EnableBandwidthManager: false,
	EnableBBR:              false,
	EnableBBRHostnsOnly:    false,
}

type BandwidthManager interface {
	BBREnabled() bool
	Enabled() bool

	UpdateBandwidthLimit(endpointID uint16, bytesPerSecond uint64, prio uint32)
	DeleteBandwidthLimit(endpointID uint16)

	UpdateIngressBandwidthLimit(endpointID uint16, bytesPerSecond uint64)
	DeleteIngressBandwidthLimit(endpointID uint16)
}

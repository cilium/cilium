// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"iter"

	"github.com/cilium/cilium/pkg/datapath/config"
)

func lxcLoadPermutations() iter.Seq[*config.BPFLXC] {
	return func(yield func(*config.BPFLXC) bool) {
		for permutation := range permute(5) {
			cfg := config.NewBPFLXC(*config.NewNode())
			cfg.Node.TracingIPOptionType = 1
			cfg.Node.DebugLB = true
			cfg.AllowICMPFragNeeded = true
			cfg.EnableICMPRule = true
			cfg.EnableConntrackAccounting = true

			cfg.Node.PolicyDenyResponseEnabled = permutation[0]
			cfg.EnableLRP = permutation[1]
			cfg.HybridRoutingEnabled = permutation[2]
			cfg.EnableARPResponder = permutation[3]
			cfg.EnableNetkit = permutation[4]

			if !yield(cfg) {
				return
			}
		}
	}
}

func hostLoadPermutations() iter.Seq[*config.BPFHost] {
	return func(yield func(*config.BPFHost) bool) {
		for permutation := range permute(4) {
			cfg := config.NewBPFHost(*config.NewNode())
			cfg.Node.TracingIPOptionType = 1
			cfg.Node.DebugLB = true
			cfg.AllowICMPFragNeeded = true
			cfg.EnableICMPRule = true
			cfg.EnableConntrackAccounting = true

			cfg.EnableRemoteNodeMasquerade = permutation[0]
			if permutation[1] {
				cfg.EthHeaderLength = 0
			} else {
				cfg.EthHeaderLength = 14
			}
			cfg.EnableL2Announcements = permutation[2]
			cfg.HybridRoutingEnabled = permutation[3]

			if !yield(cfg) {
				return
			}
		}
	}
}

func networkLoadPermutations() iter.Seq[*config.BPFNetwork] {
	return func(yield func(*config.BPFNetwork) bool) {
		cfg := config.NewBPFNetwork(*config.NewNode())
		cfg.Node.TracingIPOptionType = 1
		if !yield(cfg) {
			return
		}
	}
}

func overlayLoadPermutations() iter.Seq[*config.BPFOverlay] {
	return func(yield func(*config.BPFOverlay) bool) {
		cfg := config.NewBPFOverlay(*config.NewNode())
		cfg.Node.TracingIPOptionType = 1
		cfg.Node.DebugLB = true
		cfg.EnableConntrackAccounting = true

		if !yield(cfg) {
			return
		}
	}
}

func sockLoadPermutations() iter.Seq[*config.BPFSock] {
	return func(yield func(*config.BPFSock) bool) {
		for permutation := range permute(1) {
			cfg := config.NewBPFSock(*config.NewNode())
			cfg.Node.DebugLB = true

			cfg.EnableLRP = permutation[0]

			if !yield(cfg) {
				return
			}
		}
	}
}

func wireguardLoadPermutations() iter.Seq[*config.BPFWireguard] {
	return func(yield func(*config.BPFWireguard) bool) {
		cfg := config.NewBPFWireguard(*config.NewNode())
		cfg.Node.TracingIPOptionType = 1
		cfg.Node.DebugLB = true
		cfg.EnableConntrackAccounting = true

		if !yield(cfg) {
			return
		}
	}
}

func xdpLoadPermutations() iter.Seq[*config.BPFXDP] {
	return func(yield func(*config.BPFXDP) bool) {
		for permutation := range permute(1) {
			cfg := config.NewBPFXDP(*config.NewNode())
			cfg.Node.TracingIPOptionType = 1
			cfg.Node.DebugLB = true
			cfg.EnableConntrackAccounting = true

			cfg.EnableXDPPrefilter = permutation[0]

			if !yield(cfg) {
				return
			}
		}
	}
}

func permute(n int) iter.Seq[[]bool] {
	permutation := make([]bool, n)
	return func(yield func([]bool) bool) {
		for i := range uint64(1 << n) {
			for j := range n {
				permutation[j] = (i & (1 << j)) != 0
			}
			if !yield(permutation) {
				return
			}
		}
	}
}

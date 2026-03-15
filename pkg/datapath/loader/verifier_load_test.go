// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"iter"

	config_latest "github.com/cilium/cilium/pkg/datapath/config/latest"
)

func lxcLoadPermutations() iter.Seq[*config_latest.BPFLXC] {
	return func(yield func(*config_latest.BPFLXC) bool) {
		for permutation := range permute(5) {
			cfg := config_latest.NewBPFLXC(config_latest.NewNode())
			cfg.Node.TracingIpOptionType = 1
			cfg.Node.DebugLb = true
			cfg.AllowIcmpFragNeeded = true
			cfg.EnableIcmpRule = true
			cfg.Node.EnableConntrackAccounting = true
			cfg.EnableIpv4Fragments = true
			cfg.EnableIpv6Fragments = true

			cfg.Node.PolicyDenyResponseEnabled = permutation[0]
			cfg.EnableLrp = permutation[1]
			cfg.HybridRoutingEnabled = permutation[2]
			cfg.EnableArpResponder = permutation[3]
			cfg.EnableNetkit = permutation[4]

			if !yield(cfg) {
				return
			}
		}
	}
}

func hostLoadPermutations() iter.Seq[*config_latest.BPFHost] {
	return func(yield func(*config_latest.BPFHost) bool) {
		for permutation := range permute(4) {
			cfg := config_latest.NewBPFHost(config_latest.NewNode())
			cfg.Node.TracingIpOptionType = 1
			cfg.Node.DebugLb = true
			cfg.AllowIcmpFragNeeded = true
			cfg.EnableIcmpRule = true
			cfg.Node.EnableConntrackAccounting = true
			cfg.EnableIpv4Fragments = true
			cfg.EnableIpv6Fragments = true

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

func overlayLoadPermutations() iter.Seq[*config_latest.BPFOverlay] {
	return func(yield func(*config_latest.BPFOverlay) bool) {
		cfg := &config_latest.BPFOverlay{Node: &config_latest.Node{}}
		cfg.Node.TracingIpOptionType = 1
		cfg.Node.DebugLb = true
		cfg.Node.EnableConntrackAccounting = true

		if !yield(cfg) {
			return
		}
	}
}

func sockLoadPermutations() iter.Seq[*config_latest.BPFSock] {
	return func(yield func(*config_latest.BPFSock) bool) {
		for permutation := range permute(1) {
			cfg := config_latest.NewBPFSock(config_latest.NewNode())
			cfg.Node.DebugLb = true
			cfg.EnableIpv4Fragments = true
			cfg.EnableIpv6Fragments = true

			cfg.EnableLrp = permutation[0]

			if !yield(cfg) {
				return
			}
		}
	}
}

func wireguardLoadPermutations() iter.Seq[*config_latest.BPFWireguard] {
	return func(yield func(*config_latest.BPFWireguard) bool) {
		cfg := config_latest.NewBPFWireguard(config_latest.NewNode())
		cfg.Node.TracingIpOptionType = 1
		cfg.Node.DebugLb = true
		cfg.Node.EnableConntrackAccounting = true
		cfg.EnableIpv4Fragments = true
		cfg.EnableIpv6Fragments = true

		if !yield(cfg) {
			return
		}
	}
}

func xdpLoadPermutations() iter.Seq[*config_latest.BPFXDP] {
	return func(yield func(*config_latest.BPFXDP) bool) {
		for permutation := range permute(1) {
			cfg := config_latest.NewBPFXDP(config_latest.NewNode())
			cfg.Node.TracingIpOptionType = 1
			cfg.Node.DebugLb = true
			cfg.Node.EnableConntrackAccounting = true
			cfg.EnableIpv4Fragments = true
			cfg.EnableIpv6Fragments = true

			cfg.EnableXdpPrefilter = permutation[0]

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

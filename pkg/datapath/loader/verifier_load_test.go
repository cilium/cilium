// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"iter"

	"github.com/cilium/cilium/pkg/datapath/config"
)

func lxcLoadPermutations() iter.Seq[*config.BPFLXC] {
	return func(yield func(*config.BPFLXC) bool) {
		for permutation := range permute(4) {
			cfg := config.NewBPFLXC(*config.NewNode())
			cfg.Node.TracingIPOptionType = 1
			cfg.SecctxFromIPCache = permutation[0]
			cfg.Node.PolicyDenyResponseEnabled = permutation[1]
			cfg.AllowIcmpFragNeeded = permutation[2]
			cfg.EnableIcmpRule = permutation[3]

			if !yield(cfg) {
				return
			}
		}
	}
}

func hostLoadPermutations() iter.Seq[*config.BPFHost] {
	return func(yield func(*config.BPFHost) bool) {
		for permutation := range permute(7) {
			cfg := config.NewBPFHost(*config.NewNode())
			cfg.Node.TracingIPOptionType = 1
			cfg.SecctxFromIPCache = permutation[0]
			cfg.EnableRemoteNodeMasquerade = permutation[1]
			if permutation[2] {
				cfg.EthHeaderLength = 0
			} else {
				cfg.EthHeaderLength = 14
			}
			cfg.EnableL2Announcements = permutation[3]
			cfg.AllowIcmpFragNeeded = permutation[4]
			cfg.EnableIcmpRule = permutation[5]
			cfg.EnableNodeportAcceleration = permutation[6]

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
		for permutation := range permute(1) {
			cfg := config.NewBPFOverlay(*config.NewNode())
			cfg.Node.TracingIPOptionType = 1
			cfg.SecctxFromIPCache = permutation[0]
			if !yield(cfg) {
				return
			}
		}
	}
}

type sockConfig struct {
}

func sockLoadPermutations() iter.Seq[*sockConfig] {
	return func(yield func(*sockConfig) bool) {
		yield(&sockConfig{}) // No load time config for sock programs
	}
}

func wireguardLoadPermutations() iter.Seq[*config.BPFWireguard] {
	return func(yield func(*config.BPFWireguard) bool) {
		for permutation := range permute(1) {
			cfg := config.NewBPFWireguard(*config.NewNode())
			cfg.Node.TracingIPOptionType = 1
			cfg.SecctxFromIPCache = permutation[0]
			if !yield(cfg) {
				return
			}
		}
	}
}

func xdpLoadPermutations() iter.Seq[*config.BPFXDP] {
	return func(yield func(*config.BPFXDP) bool) {
		for permutation := range permute(2) {
			cfg := config.NewBPFXDP(*config.NewNode())
			cfg.Node.TracingIPOptionType = 1
			cfg.SecctxFromIPCache = permutation[0]
			cfg.EnableNodeportAcceleration = permutation[1]

			if !yield(cfg) {
				return
			}
		}
	}
}

func permute(n int) iter.Seq[[]bool] {
	permutation := make([]bool, n)
	return func(yield func([]bool) bool) {
		for i := uint64(0); i < (1 << n); i++ {
			for j := 0; j < n; j++ {
				permutation[j] = (i & (1 << j)) != 0
			}
			if !yield(permutation) {
				return
			}
		}
	}
}

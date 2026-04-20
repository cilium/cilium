// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"github.com/cilium/cilium/pkg/datapath/config"
)

var (
	lxcLoadPermutations       loadPermutationBuilder
	hostLoadPermutations      loadPermutationBuilder
	overlayLoadPermutations   loadPermutationBuilder
	sockLoadPermutations      loadPermutationBuilder
	wireguardLoadPermutations loadPermutationBuilder
	xdpLoadPermutations       loadPermutationBuilder
)

func init() {
	baseLXCPermutations()
	baseHostPermutations()
	baseOverlayPermutations()
	baseSockPermutations()
	baseWireguardPermutations()
	baseXDPPermutations()
}

func baseLXCPermutations() {
	lxcLoadPermutations.addConstructor(func() any { return config.NewBPFLXC(*config.NewNode()) })
	lxcLoadPermutations.addOptions(
		Always(func(t *config.BPFLXC, _ bool) {
			t.Node.TracingIPOptionType = 1
			t.Node.DebugLB = true
			t.AllowICMPFragNeeded = true
			t.EnableICMPRule = true
			t.EnableConntrackAccounting = true
			t.EnableIPv4Fragments = true
			t.EnableIPv6Fragments = true
			t.EnableARPResponder = true
			t.EnableNetkit = false
		}),

		Permute(func(t *config.BPFLXC, v bool) { t.Node.PolicyDenyResponseEnabled = v }),
		Permute(func(t *config.BPFLXC, v bool) { t.EnableLRP = v }),
		Permute(func(t *config.BPFLXC, v bool) { t.HybridRoutingEnabled = v }),
	)
}

func baseHostPermutations() {
	hostLoadPermutations.addConstructor(func() any { return config.NewBPFHost(*config.NewNode()) })
	hostLoadPermutations.addOptions(
		Always(func(t *config.BPFHost, _ bool) {
			t.Node.TracingIPOptionType = 1
			t.Node.DebugLB = true
			t.AllowICMPFragNeeded = true
			t.EnableICMPRule = true
			t.EnableConntrackAccounting = true
			t.EnableIPv4Fragments = true
			t.EnableIPv6Fragments = true
			t.EnableL2Announcements = true
		}),

		Permute(func(t *config.BPFHost, v bool) { t.Node.PolicyDenyResponseEnabled = v }),
		Permute(func(t *config.BPFHost, v bool) { t.EnableRemoteNodeMasquerade = v }),
		Permute(func(t *config.BPFHost, v bool) {
			if v {
				t.EthHeaderLength = 0
			} else {
				t.EthHeaderLength = 14
			}
		}),
		Permute(func(t *config.BPFHost, v bool) { t.HybridRoutingEnabled = v }),
	)
}

func baseOverlayPermutations() {
	overlayLoadPermutations.addConstructor(func() any { return config.NewBPFOverlay(*config.NewNode()) })
	overlayLoadPermutations.addOptions(
		Always(func(t *config.BPFOverlay, _ bool) {
			t.Node.TracingIPOptionType = 1
			t.Node.DebugLB = true
			t.EnableConntrackAccounting = true
		}),
	)
}

func baseSockPermutations() {
	sockLoadPermutations.addConstructor(func() any { return config.NewBPFSock(*config.NewNode()) })
	sockLoadPermutations.addOptions(
		Always(func(t *config.BPFSock, _ bool) {
			t.Node.DebugLB = true
			t.EnableIPv4Fragments = true
			t.EnableIPv6Fragments = true
		}),
		Permute(func(t *config.BPFSock, v bool) { t.EnableLRP = v }),
	)
}

func baseWireguardPermutations() {
	wireguardLoadPermutations.addConstructor(func() any { return config.NewBPFWireguard(*config.NewNode()) })
	wireguardLoadPermutations.addOptions(
		Always(func(t *config.BPFWireguard, _ bool) {
			t.Node.TracingIPOptionType = 1
			t.Node.DebugLB = true
			t.EnableConntrackAccounting = true
			t.EnableIPv4Fragments = true
			t.EnableIPv6Fragments = true
		}),
	)
}

func baseXDPPermutations() {
	xdpLoadPermutations.addConstructor(func() any { return config.NewBPFXDP(*config.NewNode()) })
	xdpLoadPermutations.addOptions(
		Always(func(t *config.BPFXDP, _ bool) {
			t.Node.TracingIPOptionType = 1
			t.Node.DebugLB = true
			t.EnableConntrackAccounting = true
			t.EnableIPv4Fragments = true
			t.EnableIPv6Fragments = true
		}),
		Permute(func(t *config.BPFXDP, v bool) { t.EnableXDPPrefilter = v }),
	)
}

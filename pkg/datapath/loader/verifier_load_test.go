// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"github.com/cilium/cilium/pkg/datapath/config"
)

var (
	lxcLoadPermutations       = baseLXCPermutations()
	hostLoadPermutations      = baseHostPermutations()
	overlayLoadPermutations   = baseOverlayPermutations()
	sockLoadPermutations      = baseSockPermutations()
	wireguardLoadPermutations = baseWireguardPermutations()
	xdpLoadPermutations       = baseXDPPermutations()
)

func baseLXCPermutations() *loadPermutationBuilder {
	b := new(loadPermutationBuilder)
	b.addConstructor(func() any { return config.NewBPFLXC(*config.NewNode()) })
	b.addOptions(
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

		Increment(func(t *config.BPFLXC, v bool) { t.Node.PolicyDenyResponseEnabled = v }),
		Increment(func(t *config.BPFLXC, v bool) { t.HybridRoutingEnabled = v }),
		IncrementOrPermute(func(t *config.BPFLXC, v bool) { t.EnableLRP = v }),
	)
	return b
}

func baseHostPermutations() *loadPermutationBuilder {
	b := new(loadPermutationBuilder)
	b.addConstructor(func() any { return config.NewBPFHost(*config.NewNode()) })
	b.addOptions(
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

		Increment(func(t *config.BPFHost, v bool) { t.Node.PolicyDenyResponseEnabled = v }),
		Increment(func(t *config.BPFHost, v bool) { t.EnableRemoteNodeMasquerade = v }),
		Increment(func(t *config.BPFHost, v bool) {
			if v {
				t.EthHeaderLength = 0
			} else {
				t.EthHeaderLength = 14
			}
		}),
		Increment(func(t *config.BPFHost, v bool) { t.HybridRoutingEnabled = v }),
	)
	return b
}

func baseOverlayPermutations() *loadPermutationBuilder {
	b := new(loadPermutationBuilder)
	b.addConstructor(func() any { return config.NewBPFOverlay(*config.NewNode()) })
	b.addOptions(
		Always(func(t *config.BPFOverlay, _ bool) {
			t.Node.TracingIPOptionType = 1
			t.Node.DebugLB = true
			t.EnableConntrackAccounting = true
		}),
	)
	return b
}

func baseSockPermutations() *loadPermutationBuilder {
	b := new(loadPermutationBuilder)
	b.addConstructor(func() any { return config.NewBPFSock(*config.NewNode()) })
	b.addOptions(
		Always(func(t *config.BPFSock, _ bool) {
			t.Node.DebugLB = true
			t.EnableIPv4Fragments = true
			t.EnableIPv6Fragments = true
		}),
		IncrementOrPermute(func(t *config.BPFSock, v bool) { t.EnableLRP = v }),
	)
	return b
}

func baseWireguardPermutations() *loadPermutationBuilder {
	b := new(loadPermutationBuilder)
	b.addConstructor(func() any { return config.NewBPFWireguard(*config.NewNode()) })
	b.addOptions(
		Always(func(t *config.BPFWireguard, _ bool) {
			t.Node.TracingIPOptionType = 1
			t.Node.DebugLB = true
			t.EnableConntrackAccounting = true
			t.EnableIPv4Fragments = true
			t.EnableIPv6Fragments = true
		}),
	)
	return b
}

func baseXDPPermutations() *loadPermutationBuilder {
	b := new(loadPermutationBuilder)
	b.addConstructor(func() any { return config.NewBPFXDP(*config.NewNode()) })
	b.addOptions(
		Always(func(t *config.BPFXDP, _ bool) {
			t.Node.TracingIPOptionType = 1
			t.Node.DebugLB = true
			t.EnableConntrackAccounting = true
			t.EnableIPv4Fragments = true
			t.EnableIPv6Fragments = true
		}),
		Increment(func(t *config.BPFXDP, v bool) { t.EnableXDPPrefilter = v }),
	)
	return b
}

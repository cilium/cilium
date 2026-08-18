// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/option"
)

var (
	lxcLoadPermutations       = baseLXCPermutations()
	hostLoadPermutations      = baseHostPermutations()
	overlayLoadPermutations   = baseOverlayPermutations()
	sockLoadPermutations      = baseSockPermutations()
	wireguardLoadPermutations = baseWireguardPermutations()
	xdpLoadPermutations       = baseXDPPermutations()
)

func setBasePermutations(t *config.Node) {
	t.EnableBPFHostRouting = true
	t.LBSelectionPerService = true
	t.MonitorAggregation = uint8(option.MonitorAggregationLevelMedium)
	t.TracingIPOptionType = 1
	t.DebugLB = true
	t.EventsMapRateLimit = 1000
}

func baseLXCPermutations() *loadPermutationBuilder {
	b := new(loadPermutationBuilder)
	b.addConstructor(func() any { return config.NewBPFLXC(*config.NewNode()) })
	b.addOptions(
		Always(func(t *config.BPFLXC, _ bool) {
			setBasePermutations(&t.Node)
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
		Increment(func(t *config.BPFLXC, v bool) { t.Node.EnableEndpointRoutes = v }),
		IncrementOrPermute(func(t *config.BPFLXC, v bool) { t.EnableLRP = v }),
	)
	return b
}

func baseHostPermutations() *loadPermutationBuilder {
	b := new(loadPermutationBuilder)
	b.addConstructor(func() any { return config.NewBPFHost(*config.NewNode()) })
	b.addOptions(
		Always(func(t *config.BPFHost, _ bool) {
			setBasePermutations(&t.Node)
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
		Increment(func(t *config.BPFHost, v bool) { t.Node.EnableEndpointRoutes = v }),
	)
	return b
}

func baseOverlayPermutations() *loadPermutationBuilder {
	b := new(loadPermutationBuilder)
	b.addConstructor(func() any { return config.NewBPFOverlay(*config.NewNode()) })
	b.addOptions(
		Always(func(t *config.BPFOverlay, _ bool) {
			setBasePermutations(&t.Node)
			t.EnableConntrackAccounting = true
		}),
		Increment(func(t *config.BPFOverlay, v bool) { t.Node.EnableEndpointRoutes = v }),
	)
	return b
}

func baseSockPermutations() *loadPermutationBuilder {
	b := new(loadPermutationBuilder)
	b.addConstructor(func() any { return config.NewBPFSock(*config.NewNode()) })
	b.addOptions(
		Always(func(t *config.BPFSock, _ bool) {
			setBasePermutations(&t.Node)
			t.EnableIPv4Fragments = true
			t.EnableIPv6Fragments = true
		}),
		Increment(func(t *config.BPFSock, v bool) {
			if v {
				t.MKEHost = option.HostExtensionMKE
			}
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
			setBasePermutations(&t.Node)
			t.EnableConntrackAccounting = true
			t.EnableIPv4Fragments = true
			t.EnableIPv6Fragments = true
		}),
		Increment(func(t *config.BPFWireguard, v bool) { t.Node.EnableEndpointRoutes = v }),
	)
	return b
}

func baseXDPPermutations() *loadPermutationBuilder {
	b := new(loadPermutationBuilder)
	b.addConstructor(func() any { return config.NewBPFXDP(*config.NewNode()) })
	b.addOptions(
		Always(func(t *config.BPFXDP, _ bool) {
			setBasePermutations(&t.Node)
			t.EnableConntrackAccounting = true
			t.EnableIPv4Fragments = true
			t.EnableIPv6Fragments = true
		}),
		Increment(func(t *config.BPFXDP, v bool) { t.EnableXDPPrefilter = v }),
	)
	return b
}

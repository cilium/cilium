// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"maps"

	"github.com/cilium/hive/cell"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/config"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

// progRewrites collects all registered hooks to rewrite a program's compile-time constants and maps
type progRewrites struct {
	cell.In

	LXC        []datapath.EndpointProgRewriter `group:"loader-rewrite-lxc"`
	XDP        []datapath.DeviceProgRewriter   `group:"loader-rewrite-xdp"`
	CiliumHost []datapath.EndpointProgRewriter `group:"loader-rewrite-cilium-host"`
	CiliumNet  []datapath.HostProgRewriter     `group:"loader-rewrite-cilium-net"`
	Overlay    []datapath.DeviceProgRewriter   `group:"loader-rewrite-overlay"`
	Netdev     []datapath.HostProgRewriter     `group:"loader-rewrite-netdev"`
	IPsec      []datapath.ProgRewriter         `group:"loader-rewrite-ipsec"`
	Wireguard  []datapath.DeviceProgRewriter   `group:"loader-rewrite-wireguard"`
}

// builtinRewrites contains the built-in standard rewrites for all loaded BPF programs.
// See newBuiltinRewrites below for how compile-time constants and map renames are initialized.
type builtinRewrites struct {
	cell.Out

	LXC        datapath.EndpointProgRewriter `group:"loader-rewrite-lxc"`
	XDP        datapath.DeviceProgRewriter   `group:"loader-rewrite-xdp"`
	CiliumHost datapath.EndpointProgRewriter `group:"loader-rewrite-cilium-host"`
	CiliumNet  datapath.HostProgRewriter     `group:"loader-rewrite-cilium-net"`
	Overlay    datapath.DeviceProgRewriter   `group:"loader-rewrite-overlay"`
	Netdev     datapath.HostProgRewriter     `group:"loader-rewrite-netdev"`
	IPsec      datapath.ProgRewriter         `group:"loader-rewrite-ipsec"`
	Wireguard  datapath.DeviceProgRewriter   `group:"loader-rewrite-wireguard"`
}

func newBuiltinRewrites() builtinRewrites {
	return builtinRewrites{
		LXC:        datapath.EndpointProgRewriterFn[*config.BPFLXC](endpointRewrites),
		XDP:        datapath.DeviceProgRewriterFn[*config.BPFXDP](xdpRewrites),
		CiliumHost: datapath.EndpointProgRewriterFn[*config.BPFHost](ciliumHostRewrites),
		CiliumNet:  datapath.HostProgRewriterFn[*config.BPFHost](ciliumNetRewrites),
		Overlay:    datapath.DeviceProgRewriterFn[*config.BPFOverlay](overlayRewrite),
		Netdev:     datapath.HostProgRewriterFn[*config.BPFHost](netdevRewrites),
		IPsec:      datapath.ProgRewriterFn[*config.BPFNetwork](ipsecRewrites),
		Wireguard:  datapath.DeviceProgRewriterFn[*config.BPFWireguard](wireguardRewrites),
	}
}

func applyEndpointProgRewrites(
	rewrites []datapath.EndpointProgRewriter,
	ep datapath.EndpointConfiguration,
	lnc *datapath.LocalNodeConfiguration,
) (constants []any, mapRenames map[string]string) {
	constants = make([]any, 0, len(rewrites))
	mapRenames = make(map[string]string)

	for _, rewriter := range rewrites {
		c, r := rewriter.Rewrite(ep, lnc)
		constants = append(constants, c)
		maps.Copy(mapRenames, r)
	}

	return constants, mapRenames
}

func applyDeviceProgRewrites(
	rewrites []datapath.DeviceProgRewriter,
	lnc *datapath.LocalNodeConfiguration,
	link netlink.Link,
) (constants []any, mapRenames map[string]string) {
	constants = make([]any, 0, len(rewrites))
	mapRenames = make(map[string]string)

	for _, rewriter := range rewrites {
		c, r := rewriter.Rewrite(lnc, link)
		constants = append(constants, c)
		maps.Copy(mapRenames, r)
	}

	return constants, mapRenames
}

func applyHostProgRewrites(
	rewrites []datapath.HostProgRewriter,
	ep datapath.EndpointConfiguration,
	lnc *datapath.LocalNodeConfiguration,
	link netlink.Link,
) (constants []any, mapRenames map[string]string) {
	constants = make([]any, 0, len(rewrites))
	mapRenames = make(map[string]string)

	for _, rewriter := range rewrites {
		c, r := rewriter.Rewrite(ep, lnc, link)
		constants = append(constants, c)
		maps.Copy(mapRenames, r)
	}

	return constants, mapRenames
}

func applyProgRewrites(
	rewrites []datapath.ProgRewriter,
	lnc *datapath.LocalNodeConfiguration,
) (constants []any, mapRenames map[string]string) {
	constants = make([]any, 0, len(rewrites))
	mapRenames = make(map[string]string)

	for _, rewriter := range rewrites {
		c, r := rewriter.Rewrite(lnc)
		constants = append(constants, c)
		maps.Copy(mapRenames, r)
	}

	return constants, mapRenames
}

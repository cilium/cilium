// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"io"

	"github.com/cilium/ebpf"
)

// xdpObjects receives eBPF objects for attaching to XDP interfaces. Objects
// originate from bpf_xdp.c.
type xdpObjects struct {
	Entrypoint *ebpf.Program `ebpf:"cil_xdp_entry"`
}

func (o *xdpObjects) Close() {
	bpfClose(o.Entrypoint)
}

// lxcObjects receives eBPF objects for attaching to endpoint interfaces.
// Objects originate from bpf_lxc.c.
type lxcObjects struct {
	ToContainer   *ebpf.Program `ebpf:"cil_to_container"`
	FromContainer *ebpf.Program `ebpf:"cil_from_container"`

	PolicyProg *ebpf.Program `ebpf:"cil_lxc_policy"`
	PolicyMap  *ebpf.Map     `ebpf:"cilium_call_policy"`

	EgressPolicyProg *ebpf.Program `ebpf:"cil_lxc_policy_egress"`
	EgressPolicyMap  *ebpf.Map     `ebpf:"cilium_egresscall_policy"`
}

func (o *lxcObjects) Close() {
	bpfClose(o.ToContainer, o.FromContainer, o.PolicyProg, o.PolicyMap, o.EgressPolicyProg, o.EgressPolicyMap)
}

// hostObjects receives eBPF objects for attaching to cilium_host. Objects
// originate from bpf_host.c.
type hostObjects struct {
	ToHost   *ebpf.Program `ebpf:"cil_to_host"`
	FromHost *ebpf.Program `ebpf:"cil_from_host"`

	PolicyProg *ebpf.Program `ebpf:"cil_host_policy"`
	PolicyMap  *ebpf.Map     `ebpf:"cilium_call_policy"`
}

func (o *hostObjects) Close() {
	bpfClose(o.ToHost, o.FromHost, o.PolicyProg, o.PolicyMap)
}

// hostNetObjects receives eBPF objects for attaching to cilium_net. Objects
// originate from bpf_host.c.
type hostNetObjects struct {
	ToHost *ebpf.Program `ebpf:"cil_to_host"`
}

func (o *hostNetObjects) Close() {
	bpfClose(o.ToHost)
}

// hostNetdevObjects receives eBPF objects for attaching to external interfaces.
// Objects originate from bpf_host.c.
type hostNetdevObjects struct {
	FromNetdev *ebpf.Program `ebpf:"cil_from_netdev"`
	ToNetdev   *ebpf.Program `ebpf:"cil_to_netdev"`
}

func (o *hostNetdevObjects) Close() {
	bpfClose(o.FromNetdev, o.ToNetdev)
}

// overlayObjects receives eBPF objects for attaching to overlay interfaces.
// Objects originate from bpf_overlay.c.
type overlayObjects struct {
	FromOverlay *ebpf.Program `ebpf:"cil_from_overlay"`
	ToOverlay   *ebpf.Program `ebpf:"cil_to_overlay"`
}

func (o *overlayObjects) Close() {
	bpfClose(o.FromOverlay, o.ToOverlay)
}

// networkObjects receives eBPF objects for attaching to IPsec interfaces.
// Objects originate from bpf_network.c.
type networkObjects struct {
	FromNetwork *ebpf.Program `ebpf:"cil_from_network"`
}

func (o *networkObjects) Close() {
	bpfClose(o.FromNetwork)
}

// wireguardObjects receives eBPF objects for attaching to Wireguard interfaces.
// Objects originate from bpf_wireguard.c.
type wireguardObjects struct {
	FromWireguard *ebpf.Program `ebpf:"cil_from_wireguard"`
	ToWireguard   *ebpf.Program `ebpf:"cil_to_wireguard"`
}

func (o *wireguardObjects) Close() {
	bpfClose(o.FromWireguard, o.ToWireguard)
}

func bpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

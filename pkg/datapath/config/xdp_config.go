// Code generated by dpgen. DO NOT EDIT.

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

// BPFXDP is a configuration struct for a Cilium datapath object. Warning: do
// not instantiate directly! Always use [NewBPFXDP] to ensure the default values
// configured in the ELF are honored.
type BPFXDP struct {
	// MTU of the device the bpf program is attached to (default: MTU set in
	// node_config.h by agent).
	DeviceMTU uint16 `config:"device_mtu"`
	// Ifindex of the interface the bpf program is attached to.
	InterfaceIfindex uint32 `config:"interface_ifindex"`
	// First 32 bits of the MAC address of the interface the bpf program is
	// attached to.
	InterfaceMAC1 uint32 `config:"interface_mac_1"`
	// Latter 16 bits of the MAC address of the interface the bpf program is
	// attached to.
	InterfaceMAC2 uint16 `config:"interface_mac_2"`
	// Masquerade address for IPv4 traffic.
	NATIPv4Masquerade uint32 `config:"nat_ipv4_masquerade"`
	// First half of the masquerade address for IPv6 traffic.
	NATIPv6Masquerade1 uint64 `config:"nat_ipv6_masquerade_1"`
	// Second half of the masquerade address for IPv6 traffic.
	NATIPv6Masquerade2 uint64 `config:"nat_ipv6_masquerade_2"`
}

func NewBPFXDP() *BPFXDP {
	return &BPFXDP{0x5dc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
}

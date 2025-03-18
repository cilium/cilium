// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

// Node configuration is present in all objects and doesn't have a dedicated
// ELF, so pull it out of bpf_lxc.
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_lxc.o -kind node -name Node -out node_config.go

//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_lxc.o -embed Node -kind object -name BPFLXC -out lxc_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_xdp.o -embed Node -kind object -name BPFXDP -out xdp_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_host.o -embed Node -kind object -name BPFHost -out host_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_overlay.o -embed Node -kind object -name BPFOverlay -out overlay_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_network.o -embed Node -kind object -name BPFNetwork -out network_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_wireguard.o -embed Node -kind object -name BPFWireguard -out wireguard_config.go

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_lxc.o -kind object -name BPFLXC -out lxc_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_xdp.o -kind object -name BPFXDP -out xdp_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_host.o -kind object -name BPFHost -out host_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_overlay.o -kind object -name BPFOverlay -out overlay_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_network.o -kind object -name BPFNetwork -out network_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_wireguard.o -kind object -name BPFWireguard -out wireguard_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_lxc.o -kind node -name BPFNode -out node_config.go

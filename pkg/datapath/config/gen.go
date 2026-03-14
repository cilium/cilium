// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

// Node configuration is present in all objects and doesn't have a dedicated
// ELF, so pull it out of bpf_lxc.
//go:generate go tool dpgen config --kind node --name Node --out node_config.go ../../../bpf/bpf_lxc.o

//go:generate go tool dpgen config --embed Node --kind object --name BPFLXC --out lxc_config.go ../../../bpf/bpf_lxc.o
//go:generate go tool dpgen config --embed Node --kind object --name BPFXDP --out xdp_config.go ../../../bpf/bpf_xdp.o
//go:generate go tool dpgen config --embed Node --kind object --name BPFHost --out host_config.go ../../../bpf/bpf_host.o
//go:generate go tool dpgen config --embed Node --kind object --name BPFOverlay --out overlay_config.go ../../../bpf/bpf_overlay.o
//go:generate go tool dpgen config --embed Node --kind object --name BPFWireguard --out wireguard_config.go ../../../bpf/bpf_wireguard.o
//go:generate go tool dpgen config --embed Node --kind object --name BPFSock --out sock_config.go ../../../bpf/bpf_sock.o

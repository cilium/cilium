// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

// Node configuration is present in all objects and doesn't have a dedicated
// ELF, so pull it out of bpf_lxc.
//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_lxc.o --kind node --name Node --go-out node_config.go --proto-out ../../../api/v1/datapathplugins/node_config.proto --package github.com/cilium/cilium/api/v1/datapathplugins

//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_lxc.o --embed Node --kind object --name BPFLXC --go-out lxc_config.go --proto-out ../../../api/v1/datapathplugins/lxc_config.proto --proto-import node_config.proto --package github.com/cilium/cilium/api/v1/datapathplugins
//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_xdp.o --embed Node --kind object --name BPFXDP --go-out xdp_config.go --proto-out ../../../api/v1/datapathplugins/xdp_config.proto --proto-import node_config.proto --package github.com/cilium/cilium/api/v1/datapathplugins
//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_host.o --embed Node --kind object --name BPFHost --go-out host_config.go --proto-out ../../../api/v1/datapathplugins/host_config.proto --proto-import node_config.proto --package github.com/cilium/cilium/api/v1/datapathplugins
//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_overlay.o --embed Node --kind object --name BPFOverlay --go-out overlay_config.go --proto-out ../../../api/v1/datapathplugins/overlay_config.proto --proto-import node_config.proto --package github.com/cilium/cilium/api/v1/datapathplugins
//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_wireguard.o --embed Node --kind object --name BPFWireguard --go-out wireguard_config.go --proto-out ../../../api/v1/datapathplugins/wireguard_config.proto --proto-import node_config.proto --package github.com/cilium/cilium/api/v1/datapathplugins
//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_sock.o --embed Node --kind object --name BPFSock --go-out sock_config.go --proto-out ../../../api/v1/datapathplugins/sock_config.proto --proto-import node_config.proto --package github.com/cilium/cilium/api/v1/datapathplugins

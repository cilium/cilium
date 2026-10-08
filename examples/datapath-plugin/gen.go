// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go skb ./bpf/skb.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp ./bpf/xdp.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go sock ./bpf/sock.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go sock_addr ./bpf/sock_addr.c

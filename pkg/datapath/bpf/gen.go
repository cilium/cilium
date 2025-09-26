// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package bpf provides Go skeletons containing BPF programs.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go SockTerm ../../../bpf/bpf_sock_term.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go CTMapGCMark ../../../bpf/bpf_ctmap_gc.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go CTMapGCSweep ../../../bpf/bpf_ctmap_gc_sweep.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go Probes ../../../bpf/bpf_probes.c

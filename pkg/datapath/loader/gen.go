// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package bpf provides Go skeletons containing BPF programs.
package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go sock_term ../../../bpf/bpf_sock_term.c

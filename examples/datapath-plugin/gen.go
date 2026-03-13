// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package bpf provides Go skeletons containing BPF programs.
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go plugin ./bpf/plugin.c

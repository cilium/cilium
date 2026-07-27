// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package bpf provides Go skeletons containing BPF programs.
package testprogs

//go:generate go tool github.com/cilium/ebpf/cmd/bpf2go PluginsBase ../../../../bpf/test-progs/bpf_plugins_base.c
//go:generate go tool github.com/cilium/ebpf/cmd/bpf2go PluginsHooks ../../../../bpf/test-progs/bpf_plugins_hooks.c

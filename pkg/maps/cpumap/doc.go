// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package cpumap provides a cell which loads and populates an
// eBPF map of the type BPF_MAP_TYPE_CPUMAP. This provides a centralized
// method for loading this map for XDP features which rely on the
// bpf_redirect_map() helper.
//
// The map is constructed to only perform basic redirection
// functionality. Redirecting to a second XDP program is not supported.
// +groupName=maps
package cpumap

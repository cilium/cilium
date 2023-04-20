// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

// BpfMap defines the base interface every BPF map needs to implement.
//
// Its main purpose is to register a BPF map via value group `bpf-maps`.
//
// Example:
//
//	type MapOut struct {
//		 cell.Out
//
//		 BpfMap  bpf.BpfMap `group:"bpf-maps"`
//	}
type BpfMap interface{}

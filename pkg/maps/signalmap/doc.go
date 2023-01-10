// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package signalmap represents the perf event map used to signal
// potential congestion to Cilium agent. It is primarily managed from the
// datapath; Cilium side is used to create the map only.
// +groupName=maps
package signalmap

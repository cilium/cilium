// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package eventsmap represents the perf event map used by the datapath to
// send events to the Cilium agent. It is primarily managed from the
// datapath; Cilium side is used to create the map only.
// +groupName=maps
package eventsmap

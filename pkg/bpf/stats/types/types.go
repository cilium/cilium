// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

// ProgStatsCollector collects runtime execution statistics of loaded BPF programs.
type ProgStatsCollector interface {
	CollectProgramStats(pods []k8stypes.NamespacedName, devices []string) ([]BPFProgramStats, error)
}

// BPFProgramStats encapsulates the metadata and runtime execution statistics
// for a single BPF program.
type BPFProgramStats struct {
	Info   *ebpf.ProgramInfo
	Pod    k8stypes.NamespacedName
	Device netlink.Link
	Stats  *ebpf.ProgramStats
}

// AvgRuntimeNS returns the average runtime duration of the BPF program.
func (s *BPFProgramStats) AvgRuntimeNS() time.Duration {
	if s.Stats.RunCount == 0 {
		return 0
	}

	return s.Stats.Runtime / time.Duration(s.Stats.RunCount)
}

// PodString returns the NamespacedName string representation of the associated pod,
// or an empty string if there is no associated pod.
func (s *BPFProgramStats) PodString() string {
	if s.Pod.Name == "" {
		return ""
	}

	return s.Pod.String()
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/cilium/cilium/pkg/time"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

type bpfCollector struct {
	sfg singleflight.Group

	bpfMapsCount      *prometheus.Desc
	bpfMapsMemory     *prometheus.Desc
	bpfProgramsCount  *prometheus.Desc
	bpfProgramsMemory *prometheus.Desc
}

type bpfUsage struct {
	count                 uint64
	virtualMemoryMaxBytes uint64
}

func newbpfCollector() *bpfCollector {
	return &bpfCollector{
		bpfMapsCount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_maps"),
			"Total count of BPF maps.",
			nil, nil,
		),
		bpfMapsMemory: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_maps_virtual_memory_max_bytes"),
			"BPF maps kernel max memory usage size in bytes.",
			nil, nil,
		),
		bpfProgramsCount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_progs"),
			"Total count of BPF programs.",
			nil, nil,
		),
		bpfProgramsMemory: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_progs_virtual_memory_max_bytes"),
			"BPF programs kernel max memory usage size in bytes.",
			nil, nil,
		),
	}
}

func (s *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(s, ch)
}

type memoryEntry struct {
	BytesMemlock uint64 `json:"bytes_memlock"`
}

func getBPFUsage(typ string) (bpfUsage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bpftool", "-j", typ, "show")
	out, err := cmd.Output()
	if err != nil {
		return bpfUsage{}, fmt.Errorf("unable to get bpftool output: %w", err)
	}

	var memoryEntries []memoryEntry
	err = json.Unmarshal(out, &memoryEntries)
	if err != nil {
		return bpfUsage{}, fmt.Errorf("unable to unmarshal bpftool output: %w", err)
	}
	var totalMem uint64
	for _, entry := range memoryEntries {
		totalMem += entry.BytesMemlock
	}

	return bpfUsage{
		count:                 uint64(len(memoryEntries)),
		virtualMemoryMaxBytes: totalMem,
	}, nil
}

func (s *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	type bpfUsageResults struct {
		maps     bpfUsage
		programs bpfUsage
	}

	// Avoid querying BPF multiple times concurrently, if it happens, additional callers will wait for the
	// first one to finish and reuse its resulting values.
	results, err, _ := s.sfg.Do("collect", func() (interface{}, error) {
		var (
			results = bpfUsageResults{}
			err     error
		)

		if results.maps, err = getBPFUsage("map"); err != nil {
			return results, err
		}

		if results.programs, err = getBPFUsage("prog"); err != nil {
			return results, err
		}

		return results, nil
	})

	if err != nil {
		logrus.WithError(err).Error("retrieving BPF maps & programs usage")
	}

	ch <- prometheus.MustNewConstMetric(
		s.bpfMapsCount,
		prometheus.GaugeValue,
		float64(results.(bpfUsageResults).maps.count),
	)

	ch <- prometheus.MustNewConstMetric(
		s.bpfMapsMemory,
		prometheus.GaugeValue,
		float64(results.(bpfUsageResults).maps.virtualMemoryMaxBytes),
	)

	ch <- prometheus.MustNewConstMetric(
		s.bpfProgramsCount,
		prometheus.GaugeValue,
		float64(results.(bpfUsageResults).programs.count),
	)

	ch <- prometheus.MustNewConstMetric(
		s.bpfProgramsMemory,
		prometheus.GaugeValue,
		float64(results.(bpfUsageResults).programs.virtualMemoryMaxBytes),
	)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

type bpfCollector struct {
	bpfMapsMemory *prometheus.Desc
	bpfProgMemory *prometheus.Desc
}

func newbpfCollector() *bpfCollector {
	return &bpfCollector{
		bpfMapsMemory: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_maps_virtual_memory_max_bytes"),
			"BPF maps kernel max memory usage size in bytes.",
			nil, nil,
		),
		bpfProgMemory: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_progs_virtual_memory_max_bytes"),
			"BPF programs kernel max memory usage size in bytes.",
			nil, nil,
		),
	}
}

func (s *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.bpfMapsMemory
	ch <- s.bpfProgMemory
}

type memoryEntry struct {
	BytesMemlock uint64 `json:"bytes_memlock"`
}

func getMemoryUsage(typ string) (uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bpftool", "-j", typ, "show")
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("unable to get bpftool output: %w", err)
	}

	var memoryEntries []memoryEntry
	err = json.Unmarshal(out, &memoryEntries)
	if err != nil {
		return 0, fmt.Errorf("unable to unmarshal bpftool output: %w", err)
	}
	var totalMem uint64
	for _, entry := range memoryEntries {
		totalMem += entry.BytesMemlock
	}
	return totalMem, nil
}

func (s *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	mapMem, err := getMemoryUsage("map")
	if err != nil {
		logrus.WithError(err).Error("Error while getting BPF maps memory usage")
	} else {
		ch <- prometheus.MustNewConstMetric(
			s.bpfMapsMemory,
			prometheus.GaugeValue,
			float64(mapMem),
		)
	}

	progMem, err := getMemoryUsage("prog")
	if err != nil {
		logrus.WithError(err).Error("Error while getting BPF progs memory usage")
	} else {
		ch <- prometheus.MustNewConstMetric(
			s.bpfProgMemory,
			prometheus.GaugeValue,
			float64(progMem),
		)
	}
}

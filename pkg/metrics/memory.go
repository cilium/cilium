// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"log/slog"
	"runtime"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// agentMemoryComponents are the valid values for the agent_memory_bytes component label.
var agentMemoryComponents = []string{
	"go",
	"bpf_maps",
	"bpf_progs",
	"total",
}

type agentMemoryCollector struct {
	logger *slog.Logger
	desc   *prometheus.Desc
}

func newAgentMemoryCollector(logger *slog.Logger) *agentMemoryCollector {
	return &agentMemoryCollector{
		logger: logger,
		desc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "agent_memory_bytes"),
			"Estimated memory usage of the Cilium agent in bytes, broken down by component: "+
				"go for memory in use by the Go runtime, bpf_maps and bpf_progs for the kernel memlock "+
				"of the eBPF maps and programs loaded by Cilium, and total for the sum of the three. "+
				"The eBPF memlock is not part of the agent's resident set size.",
			[]string{"component"}, nil,
		),
	}
}

func (c *agentMemoryCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *agentMemoryCollector) Collect(ch chan<- prometheus.Metric) {
	goBytes := goRuntimeInUseBytes()

	var bpfMapBytes, bpfProgBytes uint64
	bpfUsage, err := getBPFUsage()
	if err != nil {
		c.logger.Error("retrieving BPF maps & programs usage", logfields.Error, err)
	} else {
		bpfMapBytes = bpfUsage.mapBytes
		bpfProgBytes = bpfUsage.programBytes
	}
	totalBytes := goBytes + bpfMapBytes + bpfProgBytes

	for _, component := range agentMemoryComponents {
		var value uint64
		switch component {
		case "go":
			value = goBytes
		case "bpf_maps":
			value = bpfMapBytes
		case "bpf_progs":
			value = bpfProgBytes
		case "total":
			value = totalBytes
		}

		ch <- prometheus.MustNewConstMetric(
			c.desc,
			prometheus.GaugeValue,
			float64(value),
			component,
		)
	}
}

// goRuntimeInUseBytes returns memory currently in use by the Go runtime.
func goRuntimeInUseBytes() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return uint64(ms.HeapInuse + ms.StackInuse + ms.MSpanInuse + ms.MCacheInuse)
}

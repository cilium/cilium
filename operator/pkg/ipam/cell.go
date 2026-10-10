// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/operator/option"
	ipamMetrics "github.com/cilium/cilium/operator/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/metrics"
)

var allocators []cell.Cell

func Cell() cell.Cell {
	return cell.Module(
		"ip-allocator-provider",
		"Operator IP allocator provider",

		cell.Config(defaultConfig),
		cell.ProvidePrivate(newNodeWatcherJobFactory),
		metrics.Metric(ipamMetrics.NewMetrics),

		cell.Group(allocators...),
	)
}

type Config struct {
	ParallelAllocWorkers int64
	LimitIPAMAPIBurst    int
	LimitIPAMAPIQPS      float64
	IPAMReleaseExcessIPs bool
	ExcessIPReleaseDelay int
}

var defaultConfig = Config{
	ParallelAllocWorkers: 50,
	LimitIPAMAPIBurst:    20,
	LimitIPAMAPIQPS:      4.0,
	IPAMReleaseExcessIPs: false,
	ExcessIPReleaseDelay: 180,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Int64(option.ParallelAllocWorkers, defaultConfig.ParallelAllocWorkers, "Maximum number of parallel IPAM workers")
	flags.Int("limit-ipam-api-burst", defaultConfig.LimitIPAMAPIBurst, "Upper burst limit when accessing external APIs")
	flags.Float64("limit-ipam-api-qps", defaultConfig.LimitIPAMAPIQPS, "Queries per second limit when accessing external IPAM APIs")
	flags.Bool("ipam-release-excess-ips", defaultConfig.IPAMReleaseExcessIPs, "Enable releasing excess free IP addresses from cloud provider interfaces")
	flags.Int("excess-ip-release-delay", defaultConfig.ExcessIPReleaseDelay, "Number of seconds operator would wait before it releases an IP previously marked as excess")
}

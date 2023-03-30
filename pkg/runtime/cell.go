// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runtime

import (
	"context"
	"runtime/metrics"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/inctimer"
	cmx "github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

// RuntimeMetrics tracks go runtime metrics.
type RuntimeMetrics interface {
	// GetSchedulerLatency fetch scheduler GOR latency.
	GetSchedulerLatency() *metrics.Float64Histogram
}

// Config tracks the cell configuration.
type Config struct {
	// RuntimeCheckInterval tracks process metrics check interval.
	RuntimeCheckInterval time.Duration `mapstructure:"runtime-check-interval"`
}

// Flags hydrates cell config from cli args.
func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Duration(option.RuntimeCheckInterval, c.RuntimeCheckInterval, "runtime check interval")
}

// Cell creates a cell for an agent runtime perf checks.
func Cell(d time.Duration) cell.Cell {
	return cell.Module(
		"runtime",
		"Agent runtime performance",

		cell.Config(Config{RuntimeCheckInterval: d}),
		cell.Invoke(registerSchedLatencyHooks),
	)
}

func registerSchedLatencyHooks(lc hive.Lifecycle, log logrus.FieldLogger, cfg Config) {
	ctx, cancel := context.WithCancel(context.Background())
	log = rtLogger(log)

	lc.Append(hive.Hook{
		OnStart: _start(ctx, log, cfg, newGORuntimeMetrics()),
		OnStop:  _stop(cancel, log),
	})
}

func _start(ctx context.Context, log logrus.FieldLogger, cfg Config, mx RuntimeMetrics) func(hive.HookContext) error {
	return func(hive.HookContext) error {
		log.Infof("Starting runtime monitor [%v]", cfg.RuntimeCheckInterval)
		go run(ctx, log, cfg, mx)
		return nil
	}
}

func run(ctx context.Context, log logrus.FieldLogger, cfg Config, mx RuntimeMetrics) {
	collect(log, mx)
	timer, stopFn := inctimer.New()
	for {
		select {
		case <-timer.After(cfg.RuntimeCheckInterval):
			collect(log, mx)
		case <-ctx.Done():
			log.Info("Runtime monitor canceled!")
			stopFn()
			return
		}
	}
}

func collect(log logrus.FieldLogger, mx RuntimeMetrics) {
	h := mx.GetSchedulerLatency()
	if h == nil {
		return
	}
	if m := computeMedian(h); m > 0 {
		cmx.RuntimeSchedulerLatency.WithLabelValues("latency").Set(m)
	}
}

func _stop(cancel context.CancelFunc, log logrus.FieldLogger) func(hive.HookContext) error {
	return func(hive.HookContext) error {
		cancel()
		log.Info("Runtime monitor stopped")
		return nil
	}
}

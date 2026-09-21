// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package scaletozero publishes the demand for services that are scaled to
// zero, so that an autoscaler can scale them back up.
package scaletozero

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	scaletozeromap "github.com/cilium/cilium/pkg/maps/scaletozero"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/signal"
)

var Cell = cell.Module(
	"scale-to-zero",
	"Publishes the demand for services that are scaled to zero",

	metrics.Metric(newMetrics),
	cell.Provide(scaleToZeroDefines),
	cell.Invoke(registerDemandTracker),
)

// scaleToZeroDefines enables the compile-time part of the datapath support.
// Everything else is switched at load time, but whether bpf_lxc.c has the
// per-packet load-balancing tail calls is decided by the layout of the ELF:
// without them a connection held under full socket-LB would never be
// translated to a backend once the service scales up.
func scaleToZeroDefines(cfg loadbalancer.Config) defines.NodeOut {
	if !cfg.EnableScaleToZero {
		return defines.NodeOut{}
	}
	return defines.NodeOut{NodeDefines: defines.Map{"ENABLE_SCALE_TO_ZERO": "1"}}
}

type params struct {
	cell.In

	Logger         *slog.Logger
	Config         loadbalancer.Config
	ScaleToZeroMap scaletozeromap.Map
	SignalManager  signal.SignalManager
	Metrics        *scaleToZeroMetrics
}

func registerDemandTracker(p params) error {
	if !p.Config.EnableScaleToZero {
		// A datapath loaded by a previous run with the feature enabled keeps
		// emitting wake signals until it is replaced. Registering a handler
		// that drops them keeps those signals from being counted as
		// unregistered, which is what a signal nobody asked for looks like.
		if err := p.SignalManager.RegisterHandler(func(io.Reader) (string, error) { return "", nil }, signal.SignalScaleFromZero); err != nil {
			return fmt.Errorf("failed to set up no-op signal handler for disabled scale-from-zero events: %w", err)
		}
		return nil
	}

	tracker := &demandTracker{
		services: p.ScaleToZeroMap,
		window:   p.Config.ScaleToZeroIdleTimeout,
		demand:   p.Metrics.ServiceDemand,
	}
	if err := p.SignalManager.RegisterHandler(tracker.handleWake, signal.SignalScaleFromZero); err != nil {
		return fmt.Errorf("failed to set up signal handler for scale-from-zero events: %w", err)
	}

	p.Logger.Info("Publishing demand for scale-to-zero services", logfields.Timeout, p.Config.ScaleToZeroIdleTimeout)

	return nil
}

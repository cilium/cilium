// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdp

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/option"
)

// Cell is a cell that provides the configuration parameters
// for XDP based on requests from external modules.
var Cell = cell.Module(
	"datapath-xdp-config",
	"XDP configuration",

	cell.Provide(
		newConfig,

		// Determine the XDP mode requested by XDP LoadBalancer acceleration
		// settings. This is done here since the relevant LoadBalancer configuration
		// has not been modularized yet.
		//
		// Users configure the `loadbalancer.acceleration` helm value, which is
		// passed to cilium through --bpf-lb-acceleration. This flag's value is
		// stored in `option.LoadBalancerAcceleration`, which is then used during
		// DaemonConfig's population to set `DaemonConfig.NodePortAcceleration`.
		//
		// Eventually, a cell will be created to handle load balancer settings,
		// which should import this module's EnablerOut function to request an
		// XDP Mode based on the user provided settings.
		func(dcfg *option.DaemonConfig) (EnablerOut, error) {
			xdpMode, ok := map[string]AccelerationMode{
				"":                                    AccelerationModeDisabled,
				option.NodePortAccelerationDisabled:   AccelerationModeDisabled,
				option.NodePortAccelerationGeneric:    AccelerationModeGeneric,
				option.NodePortAccelerationBestEffort: AccelerationModeBestEffort,
				option.NodePortAccelerationNative:     AccelerationModeNative,
			}[dcfg.NodePortAcceleration]

			if !ok {
				return NewEnabler(AccelerationModeDisabled), fmt.Errorf("Invalid value for --%s: %s", option.NodePortAcceleration, dcfg.NodePortAcceleration)
			}

			return NewEnabler(xdpMode), nil
		},
	),

	cell.Invoke(func(c Config, l *slog.Logger) {
		l.Info("Determined final XDP mode", "acceleration-mode", c.AccelerationMode(), "mode", c.Mode())
	}),
)

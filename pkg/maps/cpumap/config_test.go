// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package cpumap

import (
	"log/slog"
	"runtime"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/datapath/xdp"
	"github.com/cilium/cilium/pkg/hive"
)

func TestConfig(t *testing.T) {
	numCPUs := runtime.NumCPU()

	tests := []struct {
		name          string
		enablers      []bool
		xdpEnabled    bool
		givesError    bool
		enabledResult bool
		checkCPUs     bool
		checkQSize    bool
	}{
		{
			name:          "cpumap is not enabled when no enablers are given and xdp disabled",
			xdpEnabled:    false,
			enabledResult: false,
		},
		{
			name:          "cpumap is not enabled when no enablers are given and xdp enabled",
			xdpEnabled:    true,
			enabledResult: false,
		},
		{
			name:          "cpumap is not enabled when false enabler is given and xdp disabled",
			enablers:      []bool{false},
			xdpEnabled:    false,
			enabledResult: false,
		},
		{
			name:          "cpumap is not enabled when false enablers is given and xdp enabled",
			enablers:      []bool{false},
			xdpEnabled:    true,
			enabledResult: false,
		},
		{
			name:          "cpumap is enabled when one enabler is given and xdp enabled",
			enablers:      []bool{true},
			xdpEnabled:    true,
			enabledResult: true,
		},
		{
			name:          "cpumap is enabled when more than one enabler is given and xdp enabled",
			enablers:      []bool{true, false, true, false},
			xdpEnabled:    true,
			enabledResult: true,
		},
		{
			name:          "numcpus is populated when enabled",
			enablers:      []bool{true},
			xdpEnabled:    true,
			enabledResult: true,
			checkCPUs:     true,
		},
		{
			name:          "qsize is populated when enabled",
			enablers:      []bool{true},
			xdpEnabled:    true,
			enabledResult: true,
			checkQSize:    true,
		},
		{
			name:          "error is returned when xdp is disabled and cpumap is enabled",
			enablers:      []bool{true},
			xdpEnabled:    false,
			givesError:    true,
			enabledResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var result Config

			enablers := []any{}
			for _, b := range test.enablers {
				enablers = append(
					enablers,
					func() EnablerOut {
						return NewEnabler(b)
					},
				)
			}

			xdpEnablers := []any{}
			if test.xdpEnabled {
				xdpEnablers = append(
					xdpEnablers,
					func() xdp.EnablerOut {
						return xdp.NewEnabler(xdp.AccelerationModeGeneric)
					},
				)
			}

			err := hive.New(
				xdp.TestCell,
				cell.Provide(xdpEnablers...),
				cell.Config(defaultUserConfig),
				cell.Provide(newConfig),
				cell.Provide(enablers...),
				cell.Invoke(func(cfg Config) { result = cfg }),
			).Populate(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)))

			if test.givesError {
				if err == nil {
					t.Error("expected error from hive but got nil")
					t.FailNow()
				}

				return
			} else if err != nil {
				t.Errorf("unexpected error from hive: %s", err.Error())
				t.FailNow()
			}

			if result.enabled != test.enabledResult {
				t.Errorf("expected enabled state to be %t, instead got %t", result.enabled, test.enabledResult)
			}

			if test.checkCPUs && result.numCPUs != uint(numCPUs) {
				t.Errorf("expected %d cpus in config, instead found %d", uint(numCPUs), result.numCPUs)
			}

			if test.checkQSize && result.qsize != defaultUserConfig.XdpCpumapQSize {
				t.Errorf("expected qsize of %d, instead found %d", result.qsize, defaultUserConfig.XdpCpumapQSize)
			}
		})
	}
}

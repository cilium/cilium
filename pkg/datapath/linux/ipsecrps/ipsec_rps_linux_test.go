// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsecrps

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/xdp"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/cpumap"
	"github.com/cilium/cilium/pkg/option"
)

func TestConf(t *testing.T) {
	type testCase struct {
		name            string
		externalXDPMode xdp.AccelerationMode
		tunnelMode      tunnel.Protocol
		enabled         bool
		userEnable      bool
		givesError      bool
		enableIPSec     bool
		enableCPUMap    bool
	}
	tests := []testCase{}

	// Iterate through all possible inputs to provide the appropriate test cases.
	// IPSec on/off; CPUMap on/off; Tunneling vxlan, geneve, off; XDP native, best-effort, generic, off.
	for _, ipsecEnabled := range []bool{true, false} {
		for _, cpumapEnabled := range []bool{true, false} {
			for _, tunnelMode := range []tunnel.Protocol{tunnel.Geneve, tunnel.VXLAN, tunnel.Disabled} {
				for _, xdpMode := range []xdp.AccelerationMode{xdp.AccelerationModeBestEffort, xdp.AccelerationModeNative, xdp.AccelerationModeGeneric, xdp.AccelerationModeDisabled} {
					// If a user disabled rps then all inputs should be ignored.
					tests = append(tests, testCase{
						name: fmt.Sprintf(
							"verify disabled with ipsec=%t cpumap=%t tunnelMode=%s xdpMode=%s",
							ipsecEnabled, cpumapEnabled, tunnelMode.String(), xdpMode,
						),
						enabled:         false,
						userEnable:      false,
						givesError:      false,
						enableIPSec:     ipsecEnabled,
						enableCPUMap:    cpumapEnabled,
						tunnelMode:      tunnelMode,
						externalXDPMode: xdpMode,
					})

					if ipsecEnabled && tunnelMode == tunnel.Disabled && xdpMode != xdp.AccelerationModeGeneric {
						// The inputs do not conflict with rps and it should be successfully enabled.
						tests = append(tests, testCase{
							name:            "verify successful enablement",
							enabled:         true,
							userEnable:      true,
							givesError:      false,
							enableIPSec:     ipsecEnabled,
							enableCPUMap:    cpumapEnabled,
							tunnelMode:      tunnelMode,
							externalXDPMode: xdpMode,
						})
					} else {
						// The inputs conflict with rps and an error should be returned.
						tests = append(tests, testCase{
							name: fmt.Sprintf(
								"verify error with ipsec=%t cpumap=%t tunnelMode=%s xdpMode=%s",
								ipsecEnabled, cpumapEnabled, tunnelMode.String(), xdpMode,
							),
							enabled:         false,
							userEnable:      true,
							givesError:      true,
							enableIPSec:     ipsecEnabled,
							enableCPUMap:    cpumapEnabled,
							tunnelMode:      tunnelMode,
							externalXDPMode: xdpMode,
						})
					}
				}
			}
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var result Config

			err := hive.New(
				xdp.TestCell,
				cpumap.TestConfigCell,
				cell.Provide(
					func() tunnel.Config {
						return tunnel.NewTestConfig(test.tunnelMode)
					},
					func() xdp.EnablerOut {
						return xdp.NewEnabler(test.externalXDPMode)
					},
					func() cpumap.EnablerOut {
						return cpumap.NewEnabler(test.enableCPUMap)
					},
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableIPSec: test.enableIPSec,
						}
					},
					func() userFlags {
						return userFlags{EnableIpsecAcceleration: test.userEnable}
					},
					newUserCfg,
					newConfig,
				),
				cell.Invoke(func(cfg Config) { result = cfg }),
			).Populate(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)))

			if test.givesError {
				if err == nil {
					t.Error("expected error from hive but got nil")
					t.FailNow()
				}
			}

			if test.enabled != result.enabled {
				t.Errorf("expected IPSec RPS to be %t, instead got %t", test.enabled, result.enabled)
			}
		})
	}
}

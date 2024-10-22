// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tunnel

import (
	"errors"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	dpcfgdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
)

var defaultTestConfig = userCfg{TunnelProtocol: string(Geneve), TunnelPort: 0}

func TestConfig(t *testing.T) {
	enabler := func(enable bool, opts ...enablerOpt) any {
		return func() EnablerOut { return NewEnabler(enable, opts...) }
	}

	tests := []struct {
		name     string
		ucfg     userCfg
		enablers []any

		shallFail      bool
		proto          Protocol
		port           uint16
		deviceName     string
		shouldAdaptMTU bool
	}{
		{
			name:      "invalid protocol",
			ucfg:      userCfg{TunnelProtocol: "invalid", TunnelPort: 0},
			shallFail: true,
		},
		{
			name:  "tunnel not enabled",
			ucfg:  defaultTestConfig,
			proto: Disabled,
		},
		{
			name:     "tunnel not enabled, with enablers",
			ucfg:     defaultTestConfig,
			enablers: []any{enabler(false), enabler(false)},
			proto:    Disabled,
		},
		{
			name:           "tunnel enabled, vxlan",
			ucfg:           userCfg{TunnelProtocol: string(VXLAN), TunnelPort: 0},
			enablers:       []any{enabler(true), enabler(false)},
			proto:          VXLAN,
			port:           defaults.TunnelPortVXLAN,
			deviceName:     defaults.VxlanDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, vxlan, custom port",
			ucfg:           userCfg{TunnelProtocol: string(VXLAN), TunnelPort: 1234},
			enablers:       []any{enabler(false), enabler(true)},
			proto:          VXLAN,
			port:           1234,
			deviceName:     defaults.VxlanDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, geneve",
			ucfg:           defaultTestConfig,
			enablers:       []any{enabler(true), enabler(true)},
			proto:          Geneve,
			port:           defaults.TunnelPortGeneve,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, geneve, custom port",
			ucfg:           userCfg{TunnelProtocol: string(Geneve), TunnelPort: 1234},
			enablers:       []any{enabler(true), enabler(false)},
			proto:          Geneve,
			port:           1234,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
		},
		{
			name: "tunnel enabled, validation function",
			ucfg: defaultTestConfig,
			enablers: []any{enabler(true, WithValidator(func(proto Protocol) error {
				if proto == Geneve {
					return errors.New("invalid protocol")
				}
				return nil
			}))},
			shallFail: true,
		},
		{
			name:           "tunnel enabled, don't need MTU adaptation, one",
			ucfg:           defaultTestConfig,
			enablers:       []any{enabler(true, WithoutMTUAdaptation()), enabler(true)},
			proto:          Geneve,
			port:           defaults.TunnelPortGeneve,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, don't need MTU adaptation, all",
			ucfg:           defaultTestConfig,
			enablers:       []any{enabler(true, WithoutMTUAdaptation()), enabler(false)},
			proto:          Geneve,
			port:           defaults.TunnelPortGeneve,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out Config

			err := hive.New(
				cell.Config(tt.ucfg),
				cell.Provide(newConfig),
				cell.Provide(tt.enablers...),
				cell.Invoke(func(tc Config) { out = tc }),
			).Populate(hivetest.Logger(t))

			if tt.shallFail {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.proto, out.Protocol())
			assert.Equal(t, tt.port, out.Port())
			assert.Equal(t, tt.deviceName, out.DeviceName())
			assert.Equal(t, tt.shouldAdaptMTU, out.ShouldAdaptMTU())
		})
	}
}

func TestConfigDatapathProvider(t *testing.T) {
	tests := []struct {
		name     string
		proto    Protocol
		expected dpcfgdef.Map
	}{
		{
			name:     "disabled",
			proto:    Disabled,
			expected: dpcfgdef.Map{},
		},
		{
			name:  "vxlan",
			proto: VXLAN,
			expected: dpcfgdef.Map{
				"TUNNEL_PROTOCOL_VXLAN":  "1",
				"TUNNEL_PROTOCOL_GENEVE": "2",
				"TUNNEL_PROTOCOL":        "1",
				"TUNNEL_PORT":            "1234",
			},
		},
		{
			name:  "geneve",
			proto: Geneve,
			expected: dpcfgdef.Map{
				"TUNNEL_PROTOCOL_VXLAN":  "1",
				"TUNNEL_PROTOCOL_GENEVE": "2",
				"TUNNEL_PROTOCOL":        "2",
				"TUNNEL_PORT":            "1234",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _ := Config{
				protocol:       tt.proto,
				port:           1234,
				deviceName:     "device",
				shouldAdaptMTU: false,
			}.datapathConfigProvider()

			assert.Equal(t, out.NodeDefines, tt.expected)
		})
	}
}

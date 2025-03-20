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

var defaultTestConfig = userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(Geneve), TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange}

func TestConfig(t *testing.T) {
	enabler := func(enable bool, opts ...enablerOpt) any {
		return func() EnablerOut { return NewEnabler(enable, opts...) }
	}

	tests := []struct {
		name     string
		ucfg     userCfg
		enablers []any

		shallFail      bool
		proto          EncapProtocol
		underlay       UnderlayProtocol
		port           uint16
		deviceName     string
		shouldAdaptMTU bool
	}{
		{
			name:      "invalid protocol",
			ucfg:      userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: "invalid", TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			shallFail: true,
		},
		{
			name:      "invalid underlay",
			ucfg:      userCfg{UnderlayProtocol: "invalid", TunnelProtocol: string(VXLAN), TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			shallFail: true,
		},
		{
			name:     "tunnel not enabled",
			ucfg:     defaultTestConfig,
			underlay: IPv4,
			proto:    Disabled,
		},
		{
			name:     "tunnel not enabled, with enablers",
			ucfg:     defaultTestConfig,
			enablers: []any{enabler(false), enabler(false)},
			underlay: IPv4,
			proto:    Disabled,
		},
		{
			name:           "tunnel enabled, vxlan",
			ucfg:           userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(VXLAN), TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			enablers:       []any{enabler(true), enabler(false)},
			underlay:       IPv4,
			proto:          VXLAN,
			port:           defaults.TunnelPortVXLAN,
			deviceName:     defaults.VxlanDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, vxlan, custom port",
			ucfg:           userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(VXLAN), TunnelPort: 1234, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			enablers:       []any{enabler(false), enabler(true)},
			underlay:       IPv4,
			proto:          VXLAN,
			port:           1234,
			deviceName:     defaults.VxlanDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, geneve",
			ucfg:           defaultTestConfig,
			enablers:       []any{enabler(true), enabler(true)},
			underlay:       IPv4,
			proto:          Geneve,
			port:           defaults.TunnelPortGeneve,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, vxlan, ipv6 underlay",
			ucfg:           userCfg{UnderlayProtocol: string(IPv6), TunnelProtocol: string(VXLAN), TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			enablers:       []any{enabler(true), enabler(true)},
			underlay:       IPv6,
			proto:          VXLAN,
			port:           defaults.TunnelPortVXLAN,
			deviceName:     defaults.VxlanDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, geneve, custom port",
			ucfg:           userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(Geneve), TunnelPort: 1234, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			enablers:       []any{enabler(true), enabler(false)},
			underlay:       IPv4,
			proto:          Geneve,
			port:           1234,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
		},
		{
			name: "tunnel enabled, validation function",
			ucfg: defaultTestConfig,
			enablers: []any{enabler(true, WithValidator(func(proto EncapProtocol) error {
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
			underlay:       IPv4,
			proto:          Geneve,
			port:           defaults.TunnelPortGeneve,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, don't need MTU adaptation, all",
			ucfg:           defaultTestConfig,
			enablers:       []any{enabler(true, WithoutMTUAdaptation()), enabler(false)},
			underlay:       IPv4,
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
			assert.Equal(t, tt.underlay, out.UnderlayProtocol())
			assert.Equal(t, tt.proto, out.EncapProtocol())
			assert.Equal(t, tt.port, out.Port())
			assert.Equal(t, tt.deviceName, out.DeviceName())
			assert.Equal(t, tt.shouldAdaptMTU, out.ShouldAdaptMTU())
		})
	}
}

func TestConfigDatapathProvider(t *testing.T) {
	tests := []struct {
		name     string
		proto    EncapProtocol
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
				"TUNNEL_SRC_PORT_LOW":    "1",
				"TUNNEL_SRC_PORT_HIGH":   "2",
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
				"TUNNEL_SRC_PORT_LOW":    "1",
				"TUNNEL_SRC_PORT_HIGH":   "2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _ := Config{
				underlay:       "ipv4",
				protocol:       tt.proto,
				port:           1234,
				srcPortLow:     1,
				srcPortHigh:    2,
				deviceName:     "device",
				shouldAdaptMTU: false,
			}.datapathConfigProvider()

			assert.Equal(t, tt.expected, out.NodeDefines)
		})
	}
}

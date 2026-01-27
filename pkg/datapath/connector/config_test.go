// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

var (
	// Fake links
	fakeLinkWireguard = &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: wgTypes.IfaceName,
		},
	}
	fakeLinkGeneve = &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name: defaults.GeneveDevice,
		},
	}
	fakeLinkVxlan = &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: defaults.VxlanDevice,
		},
	}

	// DaemonConfigs
	daemonConfigCarrierPigeon = option.DaemonConfig{
		DatapathMode:    "carrier-pigeon",
		EnableIPv4:      true,
		EnableIPv6:      true,
		EnableBPFTProxy: false,
	}
	daemonConfigVeth = option.DaemonConfig{
		DatapathMode:    datapathOption.DatapathModeVeth,
		EnableIPv4:      true,
		EnableIPv6:      true,
		EnableBPFTProxy: false,
	}
	daemonConfigVethTproxy = option.DaemonConfig{
		DatapathMode:    datapathOption.DatapathModeVeth,
		EnableIPv4:      true,
		EnableIPv6:      true,
		EnableBPFTProxy: true,
	}
	daemonConfigNetkit = option.DaemonConfig{
		DatapathMode:    datapathOption.DatapathModeNetkit,
		EnableIPv4:      true,
		EnableIPv6:      true,
		EnableBPFTProxy: false,
	}
	daemonConfigNetkitTproxy = option.DaemonConfig{
		DatapathMode:    datapathOption.DatapathModeNetkit,
		EnableIPv4:      true,
		EnableIPv6:      true,
		EnableBPFTProxy: true,
	}
	daemonConfigNetkitL2 = option.DaemonConfig{
		DatapathMode:    datapathOption.DatapathModeNetkitL2,
		EnableIPv4:      true,
		EnableIPv6:      true,
		EnableBPFTProxy: false,
	}
	daemonConfigNetkitL2Tproxy = option.DaemonConfig{
		DatapathMode:    datapathOption.DatapathModeNetkitL2,
		EnableIPv4:      true,
		EnableIPv6:      true,
		EnableBPFTProxy: true,
	}
	daemonConfigAuto = option.DaemonConfig{
		DatapathMode:    datapathOption.DatapathModeAuto,
		EnableIPv4:      true,
		EnableIPv6:      true,
		EnableBPFTProxy: false,
	}
	daemonConfigAutoTproxy = option.DaemonConfig{
		DatapathMode:    datapathOption.DatapathModeAuto,
		EnableIPv4:      true,
		EnableIPv6:      true,
		EnableBPFTProxy: true,
	}

	// WireguardConfigs
	wgConfigEnabled  = fakeTypes.WireguardConfig{EnableWireguard: true}
	wgConfigDisabled = fakeTypes.WireguardConfig{EnableWireguard: false}

	// TunnelConfigs
	tunnelConfigNative = tunnel.NewTestConfig(tunnel.Disabled)
	tunnelConfigVxlan  = tunnel.NewTestConfig(tunnel.VXLAN)
	tunnelConfigGeneve = tunnel.NewTestConfig(tunnel.Geneve)

	// ConnectorConfigs
	connectorConfigVeth = ConnectorConfig{
		configuredMode:  types.ConnectorModeVeth,
		operationalMode: types.ConnectorModeVeth,
	}
	connectorConfigNetkit = ConnectorConfig{
		configuredMode:  types.ConnectorModeNetkit,
		operationalMode: types.ConnectorModeNetkit,
	}
	connectorConfigNetkitL2 = ConnectorConfig{
		configuredMode:  types.ConnectorModeNetkitL2,
		operationalMode: types.ConnectorModeNetkitL2,
	}
	connectorConfigAuto_Veth = ConnectorConfig{
		configuredMode:  types.ConnectorModeAuto,
		operationalMode: types.ConnectorModeVeth,
	}
	connectorConfigAuto_Netkit = ConnectorConfig{
		configuredMode:  types.ConnectorModeAuto,
		operationalMode: types.ConnectorModeNetkit,
	}
)

func hostSupportsNetkit() bool {
	err := probes.HaveNetkit()
	return err == nil
}

func TestNewConfig(t *testing.T) {
	logger := hivetest.Logger(t)

	tests := []struct {
		name           string
		daemonConfig   *option.DaemonConfig
		wgAgent        *fakeTypes.WireguardAgent
		tunnelConfig   tunnel.Config
		expectedConfig *ConnectorConfig
		shouldError    bool
		shouldSkip     bool
	}{
		{
			name:           "datapath-carrier-pigeon",
			daemonConfig:   &daemonConfigCarrierPigeon,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigVeth,
			shouldError:    true,
			shouldSkip:     false,
		},
		{
			name:           "datapath-veth",
			daemonConfig:   &daemonConfigVeth,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigVeth,
			shouldError:    false,
			shouldSkip:     false,
		},
		{
			name:           "datapath-veth+tproxy",
			daemonConfig:   &daemonConfigVethTproxy,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigVeth,
			shouldError:    false,
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit",
			daemonConfig:   &daemonConfigNetkit,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkit,
			shouldError:    !hostSupportsNetkit(),
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit+tproxy",
			daemonConfig:   &daemonConfigNetkitTproxy,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkit,
			shouldError:    true,
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit-l2",
			daemonConfig:   &daemonConfigNetkitL2,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkitL2,
			shouldError:    !hostSupportsNetkit(),
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit-l2+tproxy",
			daemonConfig:   &daemonConfigNetkitL2Tproxy,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkitL2,
			shouldError:    true,
			shouldSkip:     false,
		},

		{
			name:           "datapath-auto(!netkit)+oper-veth",
			daemonConfig:   &daemonConfigAuto,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			shouldError:    false,
			shouldSkip:     hostSupportsNetkit(),
		},
		{
			name:           "datapath-auto(!netkit)+tproxy+oper-veth",
			daemonConfig:   &daemonConfigAutoTproxy,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			shouldError:    false,
			shouldSkip:     hostSupportsNetkit(),
		},
		{
			name:           "datapath-auto(netkit)+oper-netkit",
			daemonConfig:   &daemonConfigAuto,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Netkit,
			shouldError:    false,
			shouldSkip:     !hostSupportsNetkit(),
		},
		{
			name:           "datapath-auto(netkit)+tproxy+oper-veth",
			daemonConfig:   &daemonConfigAutoTproxy,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			shouldError:    false,
			shouldSkip:     !hostSupportsNetkit(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldSkip {
				t.Skip()
			}

			p := connectorParams{
				Lifecycle:    &cell.DefaultLifecycle{},
				Log:          logger,
				DaemonConfig: tt.daemonConfig,
				WgAgent:      tt.wgAgent,
				TunnelConfig: tt.tunnelConfig,
			}
			connector, err := newConfig(p)

			switch tt.shouldError {
			case true:
				assert.Error(t, err)
				assert.Nil(t, connector)
			case false:
				assert.NoError(t, err)
				assert.NotNil(t, connector)
				assert.Equal(t, tt.expectedConfig.podDeviceHeadroom, connector.podDeviceHeadroom)
				assert.Equal(t, tt.expectedConfig.podDeviceTailroom, connector.podDeviceTailroom)
				assert.Equal(t, tt.expectedConfig.configuredMode, connector.configuredMode)
				assert.Equal(t, tt.expectedConfig.operationalMode, connector.operationalMode)
			}
		})
	}
}

func TestUseTunedBufferMargins(t *testing.T) {
	logger := hivetest.Logger(t)

	tests := []struct {
		name           string
		daemonConfig   *option.DaemonConfig
		shouldSkip     bool
		expectedResult bool
	}{
		{
			name:           "datapath-veth",
			daemonConfig:   &daemonConfigVeth,
			shouldSkip:     false,
			expectedResult: false,
		},
		{
			name:           "datapath-netkit",
			daemonConfig:   &daemonConfigNetkit,
			shouldSkip:     !hostSupportsNetkit(),
			expectedResult: true,
		},
		{
			name:           "datapath-netkit-l2",
			daemonConfig:   &daemonConfigNetkitL2,
			shouldSkip:     !hostSupportsNetkit(),
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldSkip {
				t.Skip()
			}
			p := connectorParams{
				Log:          logger,
				Lifecycle:    &cell.DefaultLifecycle{},
				DaemonConfig: tt.daemonConfig,
			}
			connector, err := newConfig(p)

			assert.NoError(t, err)
			if assert.NotNil(t, connector) {
				result := connector.useTunedBufferMargins()
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

type ifBufferMargin struct {
	Headroom uint16
	Tailroom uint16
}

func (m *ifBufferMargin) query(attr netlink.Link) error {
	err := netlink.LinkAdd(attr)
	if err != nil {
		return fmt.Errorf("create fake link: %w", err)
	}

	defer netlink.LinkDel(attr)

	link, err := safenetlink.LinkByName(attr.Attrs().Name)
	if err != nil {
		return fmt.Errorf("query fake link: %w", err)
	}

	m.Headroom = link.Attrs().Headroom
	m.Tailroom = link.Attrs().Tailroom
	return nil
}

func TestPrivilegedCalculateTunedBufferMargins(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	wgMargins := &ifBufferMargin{}
	geneveMargins := &ifBufferMargin{}
	vxlanMargins := &ifBufferMargin{}

	// In order to run the following tests, we need to establish the base head
	// and tailroom buffer margins for the kernel we're running on.
	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		if err := wgMargins.query(fakeLinkWireguard); err != nil {
			return fmt.Errorf("query fake wireguard: %w", err)
		}
		if err := geneveMargins.query(fakeLinkGeneve); err != nil {
			return fmt.Errorf("query fake geneve: %w", err)
		}
		if err := vxlanMargins.query(fakeLinkVxlan); err != nil {
			return fmt.Errorf("query fake vxlan: %w", err)
		}
		return nil
	}))

	tests := []struct {
		name             string
		daemonConfig     *option.DaemonConfig
		wgAgent          *fakeTypes.WireguardAgent
		tunnelConfig     tunnel.Config
		shouldSkip       bool
		expectedHeadroom uint16
		expectedTailroom uint16
	}{
		// veth
		{
			name:             "veth+native-routing",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldSkip:       false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+native-routing+wireguard",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldSkip:       false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+geneve-routing",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldSkip:       false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+geneve-routing+wireguard",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldSkip:       false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+vxlan-routing",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldSkip:       false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+vxlan-routing+wireguard",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldSkip:       false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},

		// netkit
		{
			name:             "netkit+native-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit+native-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: wgMargins.Headroom,
			expectedTailroom: wgMargins.Tailroom,
		},
		{
			name:             "netkit+geneve-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: geneveMargins.Headroom,
			expectedTailroom: geneveMargins.Tailroom,
		},
		{
			name:             "netkit+geneve-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: geneveMargins.Headroom + wgMargins.Headroom,
			expectedTailroom: geneveMargins.Tailroom + wgMargins.Tailroom,
		},
		{
			name:             "netkit+vxlan-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: vxlanMargins.Headroom,
			expectedTailroom: vxlanMargins.Tailroom,
		},
		{
			name:             "netkit+vxlan-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: vxlanMargins.Headroom + wgMargins.Headroom,
			expectedTailroom: vxlanMargins.Tailroom + wgMargins.Tailroom,
		},

		// netkit-l2
		{
			name:             "netkit-l2+native-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit-l2+native-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: wgMargins.Headroom,
			expectedTailroom: wgMargins.Tailroom,
		},
		{
			name:             "netkit-l2+geneve-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: geneveMargins.Headroom,
			expectedTailroom: geneveMargins.Tailroom,
		},
		{
			name:             "netkit-l2+geneve-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: geneveMargins.Headroom + wgMargins.Headroom,
			expectedTailroom: geneveMargins.Tailroom + wgMargins.Tailroom,
		},
		{
			name:             "netkit-l2+vxlan-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: vxlanMargins.Headroom,
			expectedTailroom: vxlanMargins.Tailroom,
		},
		{
			name:             "netkit-l2+vxlan-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: vxlanMargins.Headroom + wgMargins.Headroom,
			expectedTailroom: vxlanMargins.Tailroom + wgMargins.Tailroom,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldSkip {
				t.Skip()
			}

			ns := netns.NewNetNS(t)
			require.NoError(t, ns.Do(func() error {
				if err := netlink.LinkAdd(fakeLinkWireguard); err != nil {
					return fmt.Errorf("create fake wireguard: %w", err)
				}
				if err := netlink.LinkAdd(fakeLinkGeneve); err != nil {
					return fmt.Errorf("create fake geneve: %w", err)
				}
				if err := netlink.LinkAdd(fakeLinkVxlan); err != nil {
					return fmt.Errorf("create fake vxlan: %w", err)
				}
				return nil
			}))

			p := connectorParams{
				Lifecycle:    &cell.DefaultLifecycle{},
				Log:          logger,
				DaemonConfig: tt.daemonConfig,
				WgAgent:      tt.wgAgent,
				TunnelConfig: tt.tunnelConfig,
			}

			connector, err := newConfig(p)

			assert.NoError(t, err)
			if assert.NotNil(t, connector) {
				require.NoError(t, ns.Do(func() error {
					return connector.calculateTunedBufferMargins()
				}))

				assert.Equal(t, tt.expectedHeadroom, connector.podDeviceHeadroom)
				assert.Equal(t, tt.expectedTailroom, connector.podDeviceTailroom)
			}
		})
	}
}

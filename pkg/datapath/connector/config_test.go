// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"errors"
	"math"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
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

type fakeLinkAttributes struct {
	Name       string
	Headroom   uint16
	Tailroom   uint16
	WasCreated bool
}

func hostSupportsNetkit() bool {
	err := probes.HaveNetkit()
	return err == nil
}

// Reuseable logic to create a test device link via netlink
func createFakeLink(ifLink netlink.Link) (*fakeLinkAttributes, error) {
	fakeAttr := &fakeLinkAttributes{Name: ifLink.Attrs().Name}

	// Attempt to create the device that allows our tests to run. It's
	// possible we're running in parallel with another test, so this could
	// already exist. Allow EEXIST errors to flow through.
	err := netlink.LinkAdd(ifLink)
	if err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
	} else {
		fakeAttr.WasCreated = true
	}

	// Re-query the kernel for the device attributes so we know what we
	// expect the connector config logic to produce.
	//
	// This is necessary because we might be on a kernel that doesn't
	// report the IFLA_HEADROOM and IFLA_TAILROOM. Or, perhaps a driver
	// changes its internal headroom/tailroom reservations at some
	// point in the future.
	fakeLink, err := safenetlink.LinkByName(fakeAttr.Name)
	if err != nil {
		destroyFakeLink(fakeAttr)
		return nil, err
	}

	fakeAttr.Headroom = fakeLink.Attrs().Headroom
	fakeAttr.Tailroom = fakeLink.Attrs().Tailroom
	return fakeAttr, nil
}

func destroyFakeLink(fakeAttr *fakeLinkAttributes) error {
	if fakeAttr.WasCreated {
		return link.DeleteByName(fakeAttr.Name)
	}
	return nil
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
		name              string
		daemonConfig      *option.DaemonConfig
		configShouldError bool
		expectedResult    bool
	}{
		{
			name:              "datapath-veth",
			daemonConfig:      &daemonConfigVeth,
			configShouldError: false,
			expectedResult:    false,
		},
		{
			name:              "datapath-netkit",
			daemonConfig:      &daemonConfigNetkit,
			configShouldError: !hostSupportsNetkit(),
			expectedResult:    true,
		},
		{
			name:              "datapath-netkit-l2",
			daemonConfig:      &daemonConfigNetkitL2,
			configShouldError: !hostSupportsNetkit(),
			expectedResult:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := connectorParams{
				Log:          logger,
				Lifecycle:    &cell.DefaultLifecycle{},
				DaemonConfig: tt.daemonConfig,
			}

			connector, err := newConfig(p)
			if tt.configShouldError {
				t.Skip()
			}

			assert.NoError(t, err)
			if assert.NotNil(t, connector) {
				result := connector.useTunedBufferMargins()
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

func TestPrivilegedCalculateTunedBufferMargins(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	// Setup fake devices so we know the underlying magins of each driver
	// on the system we're running on.
	wgAttr, err := createFakeLink(fakeLinkWireguard)
	if err != nil {
		t.Fatalf("failed to create fake device %+v: %s", fakeLinkWireguard, err)
	}
	defer destroyFakeLink(wgAttr)
	geneveAttr, err := createFakeLink(fakeLinkGeneve)
	if err != nil {
		t.Fatalf("failed to create fake device %+v: %s", fakeLinkGeneve, err)
	}
	defer destroyFakeLink(geneveAttr)
	vxlanAttr, err := createFakeLink(fakeLinkVxlan)
	if err != nil {
		t.Fatalf("failed to create fake device %+v: %s", fakeLinkVxlan, err)
	}
	defer destroyFakeLink(vxlanAttr)

	// Verify nothing overflows before we test
	assert.NotNil(t, wgAttr)
	assert.NotNil(t, geneveAttr)
	assert.NotNil(t, vxlanAttr)
	assert.Less(t,
		uint32(wgAttr.Headroom+geneveAttr.Headroom+vxlanAttr.Headroom),
		uint32(math.MaxUint16))
	assert.Less(t,
		uint32(wgAttr.Tailroom+geneveAttr.Tailroom+vxlanAttr.Tailroom),
		uint32(math.MaxUint16))

	tests := []struct {
		name              string
		daemonConfig      *option.DaemonConfig
		wgAgent           *fakeTypes.WireguardAgent
		tunnelConfig      tunnel.Config
		configShouldError bool // newConfig() error
		calcShouldError   bool // calcTunedBufferMargins() error
		expectedHeadroom  uint16
		expectedTailroom  uint16
	}{
		// veth
		{
			name:              "veth+native-routing",
			daemonConfig:      &daemonConfigVeth,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:      tunnelConfigNative,
			configShouldError: false,
			calcShouldError:   false,
			expectedHeadroom:  0,
			expectedTailroom:  0,
		},
		{
			name:              "veth+native-routing+wireguard",
			daemonConfig:      &daemonConfigVeth,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:      tunnelConfigNative,
			configShouldError: false,
			calcShouldError:   false,
			expectedHeadroom:  0,
			expectedTailroom:  0,
		},
		{
			name:              "veth+geneve-routing",
			daemonConfig:      &daemonConfigVeth,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:      tunnelConfigGeneve,
			configShouldError: false,
			calcShouldError:   false,
			expectedHeadroom:  0,
			expectedTailroom:  0,
		},
		{
			name:              "veth+geneve-routing+wireguard",
			daemonConfig:      &daemonConfigVeth,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:      tunnelConfigGeneve,
			configShouldError: false,
			calcShouldError:   false,
			expectedHeadroom:  0,
			expectedTailroom:  0,
		},
		{
			name:              "veth+vxlan-routing",
			daemonConfig:      &daemonConfigVeth,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:      tunnelConfigVxlan,
			configShouldError: false,
			calcShouldError:   false,
			expectedHeadroom:  0,
			expectedTailroom:  0,
		},
		{
			name:              "veth+vxlan-routing+wireguard",
			daemonConfig:      &daemonConfigVeth,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:      tunnelConfigVxlan,
			configShouldError: false,
			calcShouldError:   false,
			expectedHeadroom:  0,
			expectedTailroom:  0,
		},

		// netkit
		{
			name:              "netkit+native-routing",
			daemonConfig:      &daemonConfigNetkit,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:      tunnelConfigNative,
			configShouldError: !hostSupportsNetkit(),
			calcShouldError:   false,
			expectedHeadroom:  0,
			expectedTailroom:  0,
		},
		{
			name:              "netkit+native-routing+wireguard",
			daemonConfig:      &daemonConfigNetkit,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:      tunnelConfigNative,
			configShouldError: !hostSupportsNetkit(),
			calcShouldError:   false,
			expectedHeadroom:  wgAttr.Headroom,
			expectedTailroom:  wgAttr.Tailroom,
		},
		{
			name:              "netkit+geneve-routing",
			daemonConfig:      &daemonConfigNetkit,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:      tunnelConfigGeneve,
			configShouldError: !hostSupportsNetkit(),
			calcShouldError:   false,
			expectedHeadroom:  geneveAttr.Headroom,
			expectedTailroom:  geneveAttr.Tailroom,
		},
		{
			name:              "netkit+geneve-routing+wireguard",
			daemonConfig:      &daemonConfigNetkit,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:      tunnelConfigGeneve,
			configShouldError: !hostSupportsNetkit(),
			calcShouldError:   false,
			expectedHeadroom:  geneveAttr.Headroom + wgAttr.Headroom,
			expectedTailroom:  geneveAttr.Tailroom + wgAttr.Tailroom,
		},
		{
			name:              "netkit+vxlan-routing",
			daemonConfig:      &daemonConfigNetkit,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:      tunnelConfigVxlan,
			configShouldError: !hostSupportsNetkit(),
			calcShouldError:   false,
			expectedHeadroom:  vxlanAttr.Headroom,
			expectedTailroom:  vxlanAttr.Tailroom,
		},
		{
			name:              "netkit+vxlan-routing+wireguard",
			daemonConfig:      &daemonConfigNetkit,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:      tunnelConfigVxlan,
			configShouldError: !hostSupportsNetkit(),
			calcShouldError:   false,
			expectedHeadroom:  vxlanAttr.Headroom + wgAttr.Headroom,
			expectedTailroom:  vxlanAttr.Tailroom + wgAttr.Tailroom,
		},

		// netkit-l2
		{
			name:              "netkit-l2+native-routing",
			daemonConfig:      &daemonConfigNetkit,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:      tunnelConfigNative,
			configShouldError: !hostSupportsNetkit(),
			calcShouldError:   false,
			expectedHeadroom:  0,
			expectedTailroom:  0,
		},
		{
			name:              "netkit-l2+native-routing+wireguard",
			daemonConfig:      &daemonConfigNetkit,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:      tunnelConfigNative,
			configShouldError: !hostSupportsNetkit(),
			calcShouldError:   false,
			expectedHeadroom:  wgAttr.Headroom,
			expectedTailroom:  wgAttr.Tailroom,
		},
		{
			name:              "netkit-l2+geneve-routing",
			daemonConfig:      &daemonConfigNetkit,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:      tunnelConfigGeneve,
			configShouldError: !hostSupportsNetkit(),
			calcShouldError:   false,
			expectedHeadroom:  geneveAttr.Headroom,
			expectedTailroom:  geneveAttr.Tailroom,
		},
		{
			name:              "netkit-l2+geneve-routing+wireguard",
			daemonConfig:      &daemonConfigNetkit,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:      tunnelConfigGeneve,
			configShouldError: !hostSupportsNetkit(),
			calcShouldError:   false,
			expectedHeadroom:  geneveAttr.Headroom + wgAttr.Headroom,
			expectedTailroom:  geneveAttr.Tailroom + wgAttr.Tailroom,
		},
		{
			name:              "netkit-l2+vxlan-routing",
			daemonConfig:      &daemonConfigNetkit,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:      tunnelConfigVxlan,
			configShouldError: !hostSupportsNetkit(),
			calcShouldError:   false,
			expectedHeadroom:  vxlanAttr.Headroom,
			expectedTailroom:  vxlanAttr.Tailroom,
		},
		{
			name:              "netkit-l2+vxlan-routing+wireguard",
			daemonConfig:      &daemonConfigNetkit,
			wgAgent:           fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:      tunnelConfigVxlan,
			configShouldError: !hostSupportsNetkit(),
			calcShouldError:   false,
			expectedHeadroom:  vxlanAttr.Headroom + wgAttr.Headroom,
			expectedTailroom:  vxlanAttr.Tailroom + wgAttr.Tailroom,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := connectorParams{
				Lifecycle:    &cell.DefaultLifecycle{},
				Log:          logger,
				DaemonConfig: tt.daemonConfig,
				WgAgent:      tt.wgAgent,
				TunnelConfig: tt.tunnelConfig,
			}

			uninitialisedConnector := &ConnectorConfig{}

			connector, err := newConfig(p)
			if tt.configShouldError {
				t.Skip()
			}

			assert.NoError(t, err)
			assert.NotNil(t, connector)

			err = connector.calculateTunedBufferMargins()

			switch tt.calcShouldError {
			case true:
				assert.Error(t, err)
				assert.Equal(t, uninitialisedConnector, connector)

			case false:
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedHeadroom, connector.podDeviceHeadroom)
				assert.Equal(t, tt.expectedTailroom, connector.podDeviceTailroom)
			}
		})
	}
}

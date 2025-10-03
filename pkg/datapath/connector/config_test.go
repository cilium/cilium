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
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
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
		DatapathMode: datapathOption.DatapathModeVeth,
		EnableIPv4:   true,
		EnableIPv6:   true,
	}
	daemonConfigNetkit = option.DaemonConfig{
		DatapathMode: datapathOption.DatapathModeNetkit,
		EnableIPv4:   true,
		EnableIPv6:   true,
	}
	daemonConfigNetkitL2 = option.DaemonConfig{
		DatapathMode: datapathOption.DatapathModeNetkitL2,
		EnableIPv4:   true,
		EnableIPv6:   true,
	}

	// WireguardConfigs
	wgConfigEnabled  = fakeTypes.WireguardConfig{EnableWireguard: true}
	wgConfigDisabled = fakeTypes.WireguardConfig{EnableWireguard: false}

	// TunnelConfigs
	tunnelConfigNative = tunnel.NewTestConfig(tunnel.Disabled)
	tunnelConfigVxlan  = tunnel.NewTestConfig(tunnel.VXLAN)
	tunnelConfigGeneve = tunnel.NewTestConfig(tunnel.Geneve)

	// ConnectorConfigs
	ccTuningZero = ConnectorConfig{}
)

type fakeLinkAttributes struct {
	Name       string
	Headroom   uint16
	Tailroom   uint16
	WasCreated bool
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

func TestUseTunedBufferMargins(t *testing.T) {
	tests := []struct {
		name           string
		datapathMode   string
		expectedResult bool
	}{
		{
			name:           "datapath-veth",
			datapathMode:   datapathOption.DatapathModeVeth,
			expectedResult: false,
		},
		{
			name:           "datapath-netkit",
			datapathMode:   datapathOption.DatapathModeNetkit,
			expectedResult: true,
		},
		{
			name:           "datapath-netkit-l2",
			datapathMode:   datapathOption.DatapathModeNetkitL2,
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := useTunedBufferMargins(tt.datapathMode)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestNewConfig(t *testing.T) {
	logger := hivetest.Logger(t)

	tests := []struct {
		name           string
		daemonConfig   *option.DaemonConfig
		wgAgent        *fakeTypes.WireguardAgent
		tunnelConfig   tunnel.Config
		expectedConfig *ConnectorConfig
	}{
		{
			name:           "datapath-veth",
			daemonConfig:   &daemonConfigVeth,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &ccTuningZero,
		},
		{
			name:           "datapath-netkit",
			daemonConfig:   &daemonConfigNetkit,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &ccTuningZero,
		},
		{
			name:           "datapath-netkit-l2",
			daemonConfig:   &daemonConfigNetkitL2,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &ccTuningZero,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := connectorParams{
				Lifecycle:    &cell.DefaultLifecycle{},
				Log:          logger,
				Orchestrator: &fakeTypes.FakeOrchestrator{},
				DaemonConfig: tt.daemonConfig,
				WgAgent:      tt.wgAgent,
				TunnelConfig: tt.tunnelConfig,
			}
			connector := newConfig(p)

			assert.NotNil(t, connector)
			assert.Equal(t, tt.expectedConfig, connector)
		})
	}
}

func TestPrivilegedGenerateConfig(t *testing.T) {
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
		name             string
		daemonConfig     *option.DaemonConfig
		wgAgent          *fakeTypes.WireguardAgent
		tunnelConfig     tunnel.Config
		shouldError      bool
		expectedHeadroom uint16
		expectedTailroom uint16
	}{
		// veth
		{
			name:             "veth+native-routing",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+native-routing+wireguard",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+geneve-routing",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+geneve-routing+wireguard",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+vxlan-routing",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+vxlan-routing+wireguard",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},

		// netkit
		{
			name:             "netkit+native-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit+native-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: wgAttr.Headroom,
			expectedTailroom: wgAttr.Tailroom,
		},
		{
			name:             "netkit+geneve-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: geneveAttr.Headroom,
			expectedTailroom: geneveAttr.Tailroom,
		},
		{
			name:             "netkit+geneve-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: geneveAttr.Headroom + wgAttr.Headroom,
			expectedTailroom: geneveAttr.Tailroom + wgAttr.Tailroom,
		},
		{
			name:             "netkit+vxlan-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: vxlanAttr.Headroom,
			expectedTailroom: vxlanAttr.Tailroom,
		},
		{
			name:             "netkit+vxlan-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: vxlanAttr.Headroom + wgAttr.Headroom,
			expectedTailroom: vxlanAttr.Tailroom + wgAttr.Tailroom,
		},

		// netkit-l2
		{
			name:             "netkit+native-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit+native-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: wgAttr.Headroom,
			expectedTailroom: wgAttr.Tailroom,
		},
		{
			name:             "netkit+geneve-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: geneveAttr.Headroom,
			expectedTailroom: geneveAttr.Tailroom,
		},
		{
			name:             "netkit+geneve-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: geneveAttr.Headroom + wgAttr.Headroom,
			expectedTailroom: geneveAttr.Tailroom + wgAttr.Tailroom,
		},
		{
			name:             "netkit+vxlan-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: vxlanAttr.Headroom,
			expectedTailroom: vxlanAttr.Tailroom,
		},
		{
			name:             "netkit+vxlan-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: vxlanAttr.Headroom + wgAttr.Headroom,
			expectedTailroom: vxlanAttr.Tailroom + wgAttr.Tailroom,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := connectorParams{
				Lifecycle:    &cell.DefaultLifecycle{},
				Log:          logger,
				Orchestrator: &fakeTypes.FakeOrchestrator{},
				DaemonConfig: tt.daemonConfig,
				WgAgent:      tt.wgAgent,
				TunnelConfig: tt.tunnelConfig,
			}
			uninitialisedConnector := &ConnectorConfig{}
			connector := &ConnectorConfig{}

			err := generateConfig(p, connector)

			switch tt.shouldError {
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

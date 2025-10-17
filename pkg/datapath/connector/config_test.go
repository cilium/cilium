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

	// ConnectorUserConfigs
	userConfigEnabled  = types.ConnectorUserConfig{EnableTunedBufferMargins: true}
	userConfigDisabled = types.ConnectorUserConfig{EnableTunedBufferMargins: false}

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
	ccTuningDisabled = ConnectorConfig{UserConfig: userConfigDisabled}
	ccTuningZero     = ConnectorConfig{UserConfig: userConfigEnabled}
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

func TestNewConnectorConfig(t *testing.T) {
	logger := hivetest.Logger(t)

	tests := []struct {
		name           string
		userConfig     types.ConnectorUserConfig
		daemonConfig   *option.DaemonConfig
		wgAgent        *fakeTypes.WireguardAgent
		tunnelConfig   tunnel.Config
		shouldError    bool
		expectedConfig *ConnectorConfig
	}{
		// veth
		{
			name:           "veth+no-tuning",
			userConfig:     userConfigDisabled,
			daemonConfig:   &daemonConfigVeth,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			shouldError:    false,
			expectedConfig: &ccTuningDisabled,
		},
		{
			name:           "veth+tuning",
			userConfig:     userConfigEnabled,
			daemonConfig:   &daemonConfigVeth,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			shouldError:    true,
			expectedConfig: nil,
		},

		// netkit
		{
			name:           "netkit+no-tuning",
			userConfig:     userConfigDisabled,
			daemonConfig:   &daemonConfigNetkit,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			shouldError:    false,
			expectedConfig: &ccTuningDisabled,
		},
		{
			name:           "netkit+tuned",
			userConfig:     userConfigEnabled,
			daemonConfig:   &daemonConfigNetkit,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			shouldError:    false,
			expectedConfig: &ccTuningZero,
		},

		// netkit-l2
		{
			name:           "netkit-l2+no-tuning",
			userConfig:     userConfigDisabled,
			daemonConfig:   &daemonConfigNetkitL2,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			shouldError:    false,
			expectedConfig: &ccTuningDisabled,
		},
		{
			name:           "netkit-l2+tuned",
			userConfig:     userConfigEnabled,
			daemonConfig:   &daemonConfigNetkitL2,
			wgAgent:        fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			shouldError:    false,
			expectedConfig: &ccTuningZero,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := connectorParams{
				Lifecycle:    &cell.DefaultLifecycle{},
				Log:          logger,
				Orchestrator: &fakeTypes.FakeOrchestrator{},
				UserConfig:   tt.userConfig,
				DaemonConfig: tt.daemonConfig,
				WgAgent:      tt.wgAgent,
				TunnelConfig: tt.tunnelConfig,
			}
			connector, err := newConnectorConfig(p)

			switch tt.shouldError {
			case true:
				assert.Error(t, err)
				assert.Nil(t, connector)

			case false:
				assert.NoError(t, err)
				assert.NotNil(t, connector)
				assert.Equal(t, tt.expectedConfig, connector)
			}
		})
	}
}

func TestPrivilegedGenerateConnectorConfig(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	// Setup fake devices so we know the underlying magins of each driver
	// on the system we're running on.
	wgAttr, err := createFakeLink(fakeLinkWireguard)
	if err != nil {
		t.Fatalf("failed to create fake device %+v: %s", fakeLinkWireguard, err)
	}
	geneveAttr, err := createFakeLink(fakeLinkGeneve)
	if err != nil {
		t.Fatalf("failed to create fake device %+v: %s", fakeLinkGeneve, err)
	}
	vxlanAttr, err := createFakeLink(fakeLinkVxlan)
	if err != nil {
		t.Fatalf("failed to create fake device %+v: %s", fakeLinkVxlan, err)
	}

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
		userConfig       types.ConnectorUserConfig
		daemonConfig     *option.DaemonConfig
		wgAgent          *fakeTypes.WireguardAgent
		tunnelConfig     tunnel.Config
		shouldError      bool
		expectedHeadroom uint16
		expectedTailroom uint16
	}{
		// netkit, no tuning, matrix{no-encap, wg, wg+geneve, wg+vxlan, geneve, vxlan}
		{
			name:             "netkit+no-tuning",
			userConfig:       userConfigDisabled,
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit+no-tuning+wg",
			userConfig:       userConfigDisabled,
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit+no-tuning+wg+geneve",
			userConfig:       userConfigDisabled,
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit+no-tuning+wg+vxlan",
			userConfig:       userConfigDisabled,
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit+no-tuning+geneve",
			userConfig:       userConfigDisabled,
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit+no-tuning+vxlan",
			userConfig:       userConfigDisabled,
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},

		// netkit, tuned, matrix{no-encap, wg, wg+geneve, wg+vxlan, geneve, vxlan}
		{
			name:             "netkit+tuned",
			userConfig:       userConfigEnabled,
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit+tuned+wg",
			userConfig:       userConfigEnabled,
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: wgAttr.Headroom,
			expectedTailroom: wgAttr.Tailroom,
		},
		{
			name:             "netkit+tuned+wg+geneve",
			userConfig:       userConfigEnabled,
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: wgAttr.Headroom + geneveAttr.Headroom,
			expectedTailroom: wgAttr.Tailroom + geneveAttr.Tailroom,
		},
		{
			name:             "netkit+tuned+wg+vxlan",
			userConfig:       userConfigEnabled,
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: wgAttr.Headroom + vxlanAttr.Headroom,
			expectedTailroom: wgAttr.Tailroom + vxlanAttr.Tailroom,
		},
		{
			name:             "netkit+tuned+geneve",
			userConfig:       userConfigEnabled,
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: geneveAttr.Headroom,
			expectedTailroom: geneveAttr.Tailroom,
		},
		{
			name:             "netkit+tuned+vxlan",
			userConfig:       userConfigEnabled,
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: vxlanAttr.Headroom,
			expectedTailroom: vxlanAttr.Tailroom,
		},

		// netkit-l2, no tuning, matrix{no-encap, wg, wg+geneve, wg+vxlan, geneve, vxlan}
		{
			name:             "netkit-l2+no-tuning",
			userConfig:       userConfigDisabled,
			daemonConfig:     &daemonConfigNetkitL2,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit-l2+no-tuning+wg",
			userConfig:       userConfigDisabled,
			daemonConfig:     &daemonConfigNetkitL2,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit-l2+no-tuning+wg+geneve",
			userConfig:       userConfigDisabled,
			daemonConfig:     &daemonConfigNetkitL2,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit-l2+no-tuning+wg+vxlan",
			userConfig:       userConfigDisabled,
			daemonConfig:     &daemonConfigNetkitL2,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit-l2+no-tuning+geneve",
			userConfig:       userConfigDisabled,
			daemonConfig:     &daemonConfigNetkitL2,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit-l2+no-tuning+vxlan",
			userConfig:       userConfigDisabled,
			daemonConfig:     &daemonConfigNetkitL2,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},

		// netkit-l2, tuned, matrix{no-encap, wg, wg+geneve, wg+vxlan, geneve, vxlan}
		{
			name:             "netkit-l2+tuned",
			userConfig:       userConfigEnabled,
			daemonConfig:     &daemonConfigNetkitL2,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit-l2+tuned+wg",
			userConfig:       userConfigEnabled,
			daemonConfig:     &daemonConfigNetkitL2,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldError:      false,
			expectedHeadroom: wgAttr.Headroom,
			expectedTailroom: wgAttr.Tailroom,
		},
		{
			name:             "netkit-l2+tuned+wg+geneve",
			userConfig:       userConfigEnabled,
			daemonConfig:     &daemonConfigNetkitL2,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: wgAttr.Headroom + geneveAttr.Headroom,
			expectedTailroom: wgAttr.Tailroom + geneveAttr.Tailroom,
		},
		{
			name:             "netkit-l2+tuned+wg+vxlan",
			userConfig:       userConfigEnabled,
			daemonConfig:     &daemonConfigNetkitL2,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: wgAttr.Headroom + vxlanAttr.Headroom,
			expectedTailroom: wgAttr.Tailroom + vxlanAttr.Tailroom,
		},
		{
			name:             "netkit-l2+tuned+geneve",
			userConfig:       userConfigEnabled,
			daemonConfig:     &daemonConfigNetkitL2,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldError:      false,
			expectedHeadroom: geneveAttr.Headroom,
			expectedTailroom: geneveAttr.Tailroom,
		},
		{
			name:             "netkit-l2+tuned+vxlan",
			userConfig:       userConfigEnabled,
			daemonConfig:     &daemonConfigNetkitL2,
			wgAgent:          fakeTypes.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldError:      false,
			expectedHeadroom: vxlanAttr.Headroom,
			expectedTailroom: vxlanAttr.Tailroom,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := connectorParams{
				Lifecycle:    &cell.DefaultLifecycle{},
				Log:          logger,
				Orchestrator: &fakeTypes.FakeOrchestrator{},
				UserConfig:   tt.userConfig,
				DaemonConfig: tt.daemonConfig,
				WgAgent:      tt.wgAgent,
				TunnelConfig: tt.tunnelConfig,
			}
			uninitialisedConnector := &ConnectorConfig{
				UserConfig: tt.userConfig,
			}
			connector := &ConnectorConfig{
				UserConfig: tt.userConfig,
			}

			err := generateConnectorConfig(p, connector)

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

	// Destroy our fake links
	destroyFakeLink(wgAttr)
	destroyFakeLink(geneveAttr)
	destroyFakeLink(vxlanAttr)
}

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

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
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
	daemonConfigNetkitHostLegacyRouting = option.DaemonConfig{
		DatapathMode:             datapathOption.DatapathModeNetkit,
		EnableIPv4:               true,
		EnableIPv6:               true,
		UnsafeDaemonConfigOption: option.UnsafeDaemonConfig{EnableHostLegacyRouting: true},
	}
	daemonConfigNetkitIptablesMasq = option.DaemonConfig{
		DatapathMode:         datapathOption.DatapathModeNetkit,
		EnableIPv4:           true,
		EnableIPv6:           true,
		EnableIPv4Masquerade: true,
		EnableBPFMasquerade:  false,
	}
	daemonConfigNetkitEndpointRoutes = option.DaemonConfig{
		DatapathMode:         datapathOption.DatapathModeNetkit,
		EnableIPv4:           true,
		EnableIPv6:           true,
		EnableEndpointRoutes: true,
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
	daemonConfigNetkitL2HostLegacyRouting = option.DaemonConfig{
		DatapathMode:             datapathOption.DatapathModeNetkitL2,
		EnableIPv4:               true,
		EnableIPv6:               true,
		UnsafeDaemonConfigOption: option.UnsafeDaemonConfig{EnableHostLegacyRouting: true},
	}
	daemonConfigNetkitL2IptablesMasq = option.DaemonConfig{
		DatapathMode:         datapathOption.DatapathModeNetkitL2,
		EnableIPv4:           true,
		EnableIPv6:           true,
		EnableIPv4Masquerade: true,
		EnableBPFMasquerade:  false,
	}
	daemonConfigNetkitL2EndpointRoutes = option.DaemonConfig{
		DatapathMode:         datapathOption.DatapathModeNetkitL2,
		EnableIPv4:           true,
		EnableIPv6:           true,
		EnableEndpointRoutes: true,
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
	daemonConfigAutoHostLegacyRouting = option.DaemonConfig{
		DatapathMode:             datapathOption.DatapathModeAuto,
		EnableIPv4:               true,
		EnableIPv6:               true,
		UnsafeDaemonConfigOption: option.UnsafeDaemonConfig{EnableHostLegacyRouting: true},
	}
	daemonConfigAutoIptablesMasq = option.DaemonConfig{
		DatapathMode:         datapathOption.DatapathModeAuto,
		EnableIPv4:           true,
		EnableIPv6:           true,
		EnableIPv4Masquerade: true,
		EnableBPFMasquerade:  false,
	}
	daemonConfigAutoEndpointRoutes = option.DaemonConfig{
		DatapathMode:         datapathOption.DatapathModeAuto,
		EnableIPv4:           true,
		EnableIPv6:           true,
		EnableEndpointRoutes: true,
	}

	// WireguardConfigs
	wgConfigEnabled  = fakewireguard.Config{EnableWireguard: true}
	wgConfigDisabled = fakewireguard.Config{EnableWireguard: false}

	// TunnelConfigs
	tunnelConfigNative = tunnel.NewTestConfig(tunnel.Disabled)
	tunnelConfigVxlan  = tunnel.NewTestConfig(tunnel.VXLAN)
	tunnelConfigGeneve = tunnel.NewTestConfig(tunnel.Geneve)

	// ConnectorConfigs
	connectorConfigVeth = config{
		configuredMode:  ModeVeth,
		operationalMode: ModeVeth,
	}
	connectorConfigNetkit = config{
		configuredMode:  ModeNetkit,
		operationalMode: ModeNetkit,
	}
	connectorConfigNetkitL2 = config{
		configuredMode:  ModeNetkitL2,
		operationalMode: ModeNetkitL2,
	}
	connectorConfigAuto_Veth = config{
		configuredMode:  ModeAuto,
		operationalMode: ModeVeth,
	}
	connectorConfigAuto_Netkit = config{
		configuredMode:  ModeAuto,
		operationalMode: ModeNetkit,
	}
)

func hostSupportsNetkit() bool {
	err := probes.HaveNetkit()
	return err == nil
}

func hostSupportsNetkitScrub() bool {
	err := probes.HaveNetkitScrub()
	return err == nil
}

func hostSupportsNetkitTunedBufferMargins() bool {
	err := probes.HaveNetkitTunableBufferMargins()
	return err == nil
}

func TestNewConfig(t *testing.T) {
	logger := hivetest.Logger(t)

	tests := []struct {
		name           string
		daemonConfig   *option.DaemonConfig
		wgAgent        *fakewireguard.Agent
		tunnelConfig   tunnel.Config
		expectedConfig *config
		// kprConfig defaults to KubeProxyReplacement=true for every case
		// except the explicit kpr-disabled tests below. Use a pointer so
		// the zero value (struct{KubeProxyReplacement:false}) is
		// distinguishable from "not set".
		kprConfig   *loadbalancer.Config
		shouldError bool
		shouldSkip  bool
	}{
		{
			name:           "datapath-carrier-pigeon",
			daemonConfig:   &daemonConfigCarrierPigeon,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigVeth,
			shouldError:    true,
			shouldSkip:     false,
		},
		{
			name:           "datapath-veth",
			daemonConfig:   &daemonConfigVeth,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigVeth,
			shouldError:    false,
			shouldSkip:     false,
		},
		{
			name:           "datapath-veth+tproxy",
			daemonConfig:   &daemonConfigVethTproxy,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigVeth,
			shouldError:    false,
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit",
			daemonConfig:   &daemonConfigNetkit,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkit,
			shouldError:    !hostSupportsNetkit(),
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit+tproxy",
			daemonConfig:   &daemonConfigNetkitTproxy,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkit,
			shouldError:    true,
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit+legacy-host-routing",
			daemonConfig:   &daemonConfigNetkitHostLegacyRouting,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkit,
			shouldError:    true,
			shouldSkip:     false,
		},
		{
			// Explicit netkit + iptables masquerade (no BPF masq):
			// canUseNetkit refuses, agent fails to start. Operator must
			// switch to BPF masquerade.
			name:           "datapath-netkit+iptables-masq",
			daemonConfig:   &daemonConfigNetkitIptablesMasq,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkit,
			shouldError:    true,
			shouldSkip:     false,
		},
		{
			// Explicit netkit + KPR disabled: canUseNetkit refuses.
			name:           "datapath-netkit+kpr-disabled",
			daemonConfig:   &daemonConfigNetkit,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkit,
			kprConfig:      &loadbalancer.Config{UserConfig: loadbalancer.UserConfig{KubeProxyReplacement: false}},
			shouldError:    true,
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit+endpoint-routes",
			daemonConfig:   &daemonConfigNetkitEndpointRoutes,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkit,
			shouldError:    !hostSupportsNetkitScrub(),
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit-l2",
			daemonConfig:   &daemonConfigNetkitL2,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkitL2,
			shouldError:    !hostSupportsNetkit(),
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit-l2+tproxy",
			daemonConfig:   &daemonConfigNetkitL2Tproxy,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkitL2,
			shouldError:    true,
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit-l2+legacy-host-routing",
			daemonConfig:   &daemonConfigNetkitL2HostLegacyRouting,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkitL2,
			shouldError:    true,
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit-l2+iptables-masq",
			daemonConfig:   &daemonConfigNetkitL2IptablesMasq,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkitL2,
			shouldError:    true,
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit-l2+kpr-disabled",
			daemonConfig:   &daemonConfigNetkitL2,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkitL2,
			kprConfig:      &loadbalancer.Config{UserConfig: loadbalancer.UserConfig{KubeProxyReplacement: false}},
			shouldError:    true,
			shouldSkip:     false,
		},
		{
			name:           "datapath-netkit-l2+endpoint-routes",
			daemonConfig:   &daemonConfigNetkitL2EndpointRoutes,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigNetkitL2,
			shouldError:    !hostSupportsNetkitScrub(),
			shouldSkip:     false,
		},
		{
			name:           "datapath-auto(!netkit)+oper-veth",
			daemonConfig:   &daemonConfigAuto,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			shouldError:    false,
			shouldSkip:     hostSupportsNetkit(),
		},
		{
			name:           "datapath-auto(!netkit)+tproxy+oper-veth",
			daemonConfig:   &daemonConfigAutoTproxy,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			shouldError:    false,
			shouldSkip:     hostSupportsNetkit(),
		},
		{
			name:           "datapath-auto(!netkit)+legacy-host-routing+oper-veth",
			daemonConfig:   &daemonConfigAutoHostLegacyRouting,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			shouldError:    false,
			shouldSkip:     hostSupportsNetkit(),
		},
		{
			// Old kernel without netkit support: auto must already pick
			// veth regardless of iptables masquerade. No regression risk
			// here, but the symmetric case below (with netkit support)
			// is the one this fix is really protecting.
			name:           "datapath-auto(!netkit)+iptables-masq+oper-veth",
			daemonConfig:   &daemonConfigAutoIptablesMasq,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			shouldError:    false,
			shouldSkip:     hostSupportsNetkit(),
		},
		{
			name:           "datapath-auto(!netkit)+kpr-disabled+oper-veth",
			daemonConfig:   &daemonConfigAuto,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			kprConfig:      &loadbalancer.Config{UserConfig: loadbalancer.UserConfig{KubeProxyReplacement: false}},
			shouldError:    false,
			shouldSkip:     hostSupportsNetkit(),
		},
		{
			name:           "datapath-auto(netkit)+oper-netkit",
			daemonConfig:   &daemonConfigAuto,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Netkit,
			shouldError:    false,
			shouldSkip:     !hostSupportsNetkit(),
		},
		{
			name:           "datapath-auto(netkit)+tproxy+oper-veth",
			daemonConfig:   &daemonConfigAutoTproxy,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			shouldError:    false,
			shouldSkip:     !hostSupportsNetkit(),
		},
		{
			name:           "datapath-auto(netkit)+host-legacy-routing+oper-veth",
			daemonConfig:   &daemonConfigAutoHostLegacyRouting,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			shouldError:    false,
			shouldSkip:     !hostSupportsNetkit(),
		},
		{
			// This is the regression-protection case: on a kernel that
			// newly supports netkit, auto must still pick veth when the
			// rest of the config would force the kpr-initializer to fall
			// back to legacy routing (iptables masq without bpf masq).
			// Otherwise a working auto+veth cluster on an older kernel
			// would break after a kernel upgrade.
			name:           "datapath-auto(netkit)+iptables-masq+oper-veth",
			daemonConfig:   &daemonConfigAutoIptablesMasq,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			shouldError:    false,
			shouldSkip:     !hostSupportsNetkit(),
		},
		{
			// Same regression case for kube-proxy-replacement disabled.
			name:           "datapath-auto(netkit)+kpr-disabled+oper-veth",
			daemonConfig:   &daemonConfigAuto,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			kprConfig:      &loadbalancer.Config{UserConfig: loadbalancer.UserConfig{KubeProxyReplacement: false}},
			shouldError:    false,
			shouldSkip:     !hostSupportsNetkit(),
		},
		{
			name:           "datapath-auto(netkit,scrub)+endpoint-routes+oper-netkit",
			daemonConfig:   &daemonConfigAutoEndpointRoutes,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Netkit,
			shouldError:    false,
			shouldSkip:     !hostSupportsNetkitScrub(),
		},
		{
			name:           "datapath-auto(netkit,!scrub)+endpoint-routes+oper-veth",
			daemonConfig:   &daemonConfigAutoEndpointRoutes,
			wgAgent:        fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:   tunnelConfigNative,
			expectedConfig: &connectorConfigAuto_Veth,
			shouldError:    false,
			shouldSkip:     hostSupportsNetkitScrub(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldSkip {
				t.Skip()
			}

			kprCfg := loadbalancer.Config{UserConfig: loadbalancer.UserConfig{KubeProxyReplacement: true}}
			if tt.kprConfig != nil {
				kprCfg = *tt.kprConfig
			}
			p := connectorParams{
				Lifecycle:    &cell.DefaultLifecycle{},
				Log:          logger,
				DaemonConfig: tt.daemonConfig,
				WgAgent:      tt.wgAgent,
				TunnelConfig: tt.tunnelConfig,
				LBConfig:     kprCfg,
			}
			connector, err := newConfig(p)

			switch tt.shouldError {
			case true:
				require.Error(t, err)
				require.Nil(t, connector)
			case false:
				require.NoError(t, err)
				require.NotNil(t, connector)
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
				LBConfig:     loadbalancer.Config{UserConfig: loadbalancer.UserConfig{KubeProxyReplacement: true}},
			}
			connector, err := newConfig(p)

			require.NoError(t, err)
			require.NotNil(t, connector)

			result := connector.useTunedBufferMargins()
			assert.Equal(t, tt.expectedResult, result)
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
		wgAgent          *fakewireguard.Agent
		tunnelConfig     tunnel.Config
		shouldSkip       bool
		expectedHeadroom uint16
		expectedTailroom uint16
	}{
		// veth
		{
			name:             "veth+native-routing",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldSkip:       false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+native-routing+wireguard",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldSkip:       false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+geneve-routing",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldSkip:       false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+geneve-routing+wireguard",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldSkip:       false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+vxlan-routing",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldSkip:       false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "veth+vxlan-routing+wireguard",
			daemonConfig:     &daemonConfigVeth,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldSkip:       false,
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},

		// netkit
		{
			name:             "netkit+native-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit+native-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: wgMargins.Headroom,
			expectedTailroom: wgMargins.Tailroom,
		},
		{
			name:             "netkit+geneve-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: geneveMargins.Headroom,
			expectedTailroom: geneveMargins.Tailroom,
		},
		{
			name:             "netkit+geneve-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: geneveMargins.Headroom + wgMargins.Headroom,
			expectedTailroom: geneveMargins.Tailroom + wgMargins.Tailroom,
		},
		{
			name:             "netkit+vxlan-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: vxlanMargins.Headroom,
			expectedTailroom: vxlanMargins.Tailroom,
		},
		{
			name:             "netkit+vxlan-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: vxlanMargins.Headroom + wgMargins.Headroom,
			expectedTailroom: vxlanMargins.Tailroom + wgMargins.Tailroom,
		},

		// netkit-l2
		{
			name:             "netkit-l2+native-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigNative,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: 0,
			expectedTailroom: 0,
		},
		{
			name:             "netkit-l2+native-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigNative,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: wgMargins.Headroom,
			expectedTailroom: wgMargins.Tailroom,
		},
		{
			name:             "netkit-l2+geneve-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: geneveMargins.Headroom,
			expectedTailroom: geneveMargins.Tailroom,
		},
		{
			name:             "netkit-l2+geneve-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigEnabled),
			tunnelConfig:     tunnelConfigGeneve,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: geneveMargins.Headroom + wgMargins.Headroom,
			expectedTailroom: geneveMargins.Tailroom + wgMargins.Tailroom,
		},
		{
			name:             "netkit-l2+vxlan-routing",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigDisabled),
			tunnelConfig:     tunnelConfigVxlan,
			shouldSkip:       !hostSupportsNetkit(),
			expectedHeadroom: vxlanMargins.Headroom,
			expectedTailroom: vxlanMargins.Tailroom,
		},
		{
			name:             "netkit-l2+vxlan-routing+wireguard",
			daemonConfig:     &daemonConfigNetkit,
			wgAgent:          fakewireguard.NewTestAgent(wgConfigEnabled),
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
				LBConfig:     loadbalancer.Config{UserConfig: loadbalancer.UserConfig{KubeProxyReplacement: true}},
			}

			connector, err := newConfig(p)

			require.NoError(t, err)
			require.NotNil(t, connector)
			require.NoError(t, ns.Do(func() error {
				return connector.calculateTunedBufferMargins()
			}))
			assert.Equal(t, tt.expectedHeadroom, connector.podDeviceHeadroom)
			assert.Equal(t, tt.expectedTailroom, connector.podDeviceTailroom)
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"fmt"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"

	"github.com/stretchr/testify/assert"
)

type mockFeaturesParams struct {
	TunnelConfig                        tunnel.EncapProtocol
	CNIChainingMode                     string
	MutualAuth                          bool
	BandwidthManager                    bool
	bigTCPMock                          bigTCPMock
	L2PodAnnouncement                   bool
	isDynamicConfigSourceKindNodeConfig bool
}

func (m mockFeaturesParams) TunnelProtocol() tunnel.EncapProtocol {
	return m.TunnelConfig
}

func (m mockFeaturesParams) GetChainingMode() string {
	return m.CNIChainingMode
}

func (m mockFeaturesParams) IsMutualAuthEnabled() bool {
	return m.MutualAuth
}

func (m mockFeaturesParams) IsBandwidthManagerEnabled() bool {
	return m.BandwidthManager
}

func (m mockFeaturesParams) BigTCPConfig() types.BigTCPConfig {
	return m.bigTCPMock
}

func (m mockFeaturesParams) IsL2PodAnnouncementEnabled() bool {
	return m.L2PodAnnouncement
}

func (m mockFeaturesParams) IsDynamicConfigSourceKindNodeConfig() bool {
	return m.isDynamicConfigSourceKindNodeConfig
}

type bigTCPMock struct {
	ipv4Enabled bool
	ipv6Enabled bool
}

func (b bigTCPMock) IsIPv4Enabled() bool {
	return b.ipv4Enabled
}

func (b bigTCPMock) IsIPv6Enabled() bool {
	return b.ipv6Enabled
}

func TestUpdateNetworkMode(t *testing.T) {
	tests := []struct {
		name         string
		tunnelMode   string
		tunnelProto  tunnel.EncapProtocol
		expectedMode string
	}{
		{
			name:         "Direct routing mode",
			tunnelMode:   option.RoutingModeNative,
			expectedMode: networkModeDirectRouting,
		},
		{
			name:         "Overlay VXLAN mode",
			tunnelMode:   option.RoutingModeTunnel,
			tunnelProto:  tunnel.VXLAN,
			expectedMode: networkModeOverlayVXLAN,
		},
		{
			name:         "Overlay Geneve mode",
			tunnelMode:   option.RoutingModeTunnel,
			tunnelProto:  tunnel.Geneve,
			expectedMode: networkModeOverlayGENEVE,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
				RoutingMode:            tt.tunnelMode,
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				TunnelConfig:    tt.tunnelProto,
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			// Check that only the expected mode's counter is incremented
			for _, mode := range defaultNetworkModes {
				counter, err := metrics.DPMode.GetMetricWithLabelValues(mode)
				assert.NoError(t, err)

				counterValue := counter.Get()
				if mode == tt.expectedMode {
					assert.Equal(t, float64(1), counterValue, "Expected mode %s to be incremented", mode)
				} else {
					assert.Equal(t, float64(0), counterValue, "Expected mode %s to remain at 0", mode)
				}
			}
		})
	}
}

func TestUpdateIPAMMode(t *testing.T) {
	type testCase struct {
		name         string
		IPAMMode     string
		expectedMode string
	}
	var tests []testCase
	for _, mode := range defaultIPAMModes {
		tests = append(tests, testCase{
			name:         fmt.Sprintf("IPAM %s mode", mode),
			IPAMMode:     mode,
			expectedMode: mode,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
				IPAM:                   tt.IPAMMode,
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			// Check that only the expected mode's counter is incremented
			for _, mode := range defaultIPAMModes {
				counter, err := metrics.CPIPAM.GetMetricWithLabelValues(mode)
				assert.NoError(t, err)

				counterValue := counter.Get()
				if mode == tt.expectedMode {
					assert.Equal(t, float64(1), counterValue, "Expected mode %s to be incremented", mode)
				} else {
					assert.Equal(t, float64(0), counterValue, "Expected mode %s to remain at 0", mode)
				}
			}
		})
	}
}

func TestUpdateCNIChainingMode(t *testing.T) {
	type testCase struct {
		name         string
		chainingMode string
		expectedMode string
	}
	var tests []testCase
	for _, mode := range defaultChainingModes {
		tests = append(tests, testCase{
			name:         fmt.Sprintf("CNI mode %s", mode),
			chainingMode: mode,
			expectedMode: mode,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: tt.chainingMode,
			}

			metrics.update(params, config, lbConfig)

			// Check that only the expected mode's counter is incremented
			for _, mode := range defaultChainingModes {
				counter, err := metrics.DPChaining.GetMetricWithLabelValues(mode)
				assert.NoError(t, err)

				counterValue := counter.Get()
				if mode == tt.expectedMode {
					assert.Equal(t, float64(1), counterValue, "Expected mode %s to be incremented", mode)
				} else {
					assert.Equal(t, float64(0), counterValue, "Expected mode %s to remain at 0", mode)
				}
			}
		})
	}
}

func TestUpdateInternetProtocol(t *testing.T) {
	tests := []struct {
		name             string
		enableIPv4       bool
		enableIPv6       bool
		expectedProtocol string
	}{
		{
			name:             "IPv4-only",
			enableIPv4:       true,
			expectedProtocol: networkIPv4,
		},
		{
			name:             "IPv6-only",
			enableIPv6:       true,
			expectedProtocol: networkIPv6,
		},
		{
			name:             "IPv4-IPv6-dual-stack",
			enableIPv4:       true,
			enableIPv6:       true,
			expectedProtocol: networkDualStack,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
				EnableIPv4:             tt.enableIPv4,
				EnableIPv6:             tt.enableIPv6,
			}
			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			// Check that only the expected mode's counter is incremented
			for _, mode := range defaultChainingModes {
				counter, err := metrics.DPIP.GetMetricWithLabelValues(mode)
				assert.NoError(t, err)

				counterValue := counter.Get()
				if mode == tt.expectedProtocol {
					assert.Equal(t, float64(1), counterValue, "Expected mode %s to be incremented", mode)
				} else {
					assert.Equal(t, float64(0), counterValue, "Expected mode %s to remain at 0", mode)
				}
			}
		})
	}
}

func TestUpdateIdentityAllocationMode(t *testing.T) {
	type testCase struct {
		name                   string
		identityAllocationMode string
		expectedMode           string
	}
	var tests []testCase
	for _, mode := range defaultIdentityAllocationModes {
		tests = append(tests, testCase{
			name:                   fmt.Sprintf("Identity Allocation mode %s", mode),
			identityAllocationMode: mode,
			expectedMode:           mode,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
				DatapathMode:           defaultDeviceModes[0],
				IdentityAllocationMode: tt.identityAllocationMode,
			}
			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			// Check that only the expected mode's counter is incremented
			for _, mode := range defaultIdentityAllocationModes {
				counter, err := metrics.CPIdentityAllocation.GetMetricWithLabelValues(mode)
				assert.NoError(t, err)

				counterValue := counter.Get()
				if mode == tt.expectedMode {
					assert.Equal(t, float64(1), counterValue, "Expected mode %s to be incremented", mode)
				} else {
					assert.Equal(t, float64(0), counterValue, "Expected mode %s to remain at 0", mode)
				}
			}
		})
	}
}

func TestUpdateCiliumEndpointSlices(t *testing.T) {
	tests := []struct {
		name      string
		enableCES bool
		expected  float64
	}{
		{
			name:      "Enable CES",
			enableCES: true,
			expected:  1,
		},
		{
			name:      "Disable CES",
			enableCES: false,
			expected:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                      defaultIPAMModes[0],
				EnableIPv4:                true,
				IdentityAllocationMode:    defaultIdentityAllocationModes[0],
				DatapathMode:              defaultDeviceModes[0],
				NodePortAcceleration:      defaultNodePortModeAccelerations[0],
				EnableCiliumEndpointSlice: tt.enableCES,
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.CPCiliumEndpointSlicesEnabled.Get()

			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableCES, counterValue)
		})
	}
}

func TestUpdateDeviceMode(t *testing.T) {
	type testCase struct {
		name         string
		deviceMode   string
		expectedMode string
	}
	var tests []testCase
	for _, mode := range defaultDeviceModes {
		tests = append(tests, testCase{
			name:         fmt.Sprintf("Device %s mode", mode),
			deviceMode:   mode,
			expectedMode: mode,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
				DatapathMode:           tt.deviceMode,
			}
			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			// Check that only the expected mode's counter is incremented
			for _, mode := range defaultDeviceModes {
				counter, err := metrics.DPDeviceConfig.GetMetricWithLabelValues(mode)
				assert.NoError(t, err)

				counterValue := counter.Get()
				if mode == tt.expectedMode {
					assert.Equal(t, float64(1), counterValue, "Expected mode %s to be incremented", mode)
				} else {
					assert.Equal(t, float64(0), counterValue, "Expected mode %s to remain at 0", mode)
				}
			}
		})
	}
}

func TestUpdateHostFirewall(t *testing.T) {
	tests := []struct {
		name               string
		enableHostFirewall bool
		expected           float64
	}{
		{
			name:               "Host firewall enabled",
			enableHostFirewall: true,
			expected:           1,
		},
		{
			name:               "Host firewall disabled",
			enableHostFirewall: false,
			expected:           0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
				EnableHostFirewall:     tt.enableHostFirewall,
			}
			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.NPHostFirewallEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableHostFirewall, counterValue)
		})
	}
}

func TestUpdateLocalRedirectPolicies(t *testing.T) {
	tests := []struct {
		name      string
		enableLRP bool
		expected  float64
	}{
		{
			name:      "LRP enabled",
			enableLRP: true,
			expected:  1,
		},
		{
			name:      "LRP disabled",
			enableLRP: false,
			expected:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                      defaultIPAMModes[0],
				EnableIPv4:                true,
				IdentityAllocationMode:    defaultIdentityAllocationModes[0],
				DatapathMode:              defaultDeviceModes[0],
				NodePortAcceleration:      defaultNodePortModeAccelerations[0],
				EnableLocalRedirectPolicy: tt.enableLRP,
			}
			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.NPLocalRedirectPolicyEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableLRP, counterValue)
		})
	}
}

func TestUpdateMutualAuth(t *testing.T) {
	tests := []struct {
		name             string
		enableMutualAuth bool
		expected         float64
	}{
		{
			name:             "MutualAuth enabled",
			enableMutualAuth: true,
			expected:         1,
		},
		{
			name:             "MutualAuth disabled",
			enableMutualAuth: false,
			expected:         0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
				MutualAuth:      tt.enableMutualAuth,
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.NPMutualAuthEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableMutualAuth, counterValue)
		})
	}
}

func TestUpdateNonDefaultDeny(t *testing.T) {
	tests := []struct {
		name                 string
		enableNonDefaultDeny bool
		expected             float64
	}{
		{
			name:                 "NonDefaultDeny enabled",
			enableNonDefaultDeny: true,
			expected:             1,
		},
		{
			name:                 "NonDefaultDeny disabled",
			enableNonDefaultDeny: false,
			expected:             0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                         defaultIPAMModes[0],
				EnableIPv4:                   true,
				IdentityAllocationMode:       defaultIdentityAllocationModes[0],
				DatapathMode:                 defaultDeviceModes[0],
				NodePortAcceleration:         defaultNodePortModeAccelerations[0],
				EnableNonDefaultDenyPolicies: tt.enableNonDefaultDeny,
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.NPNonDefaultDenyEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableNonDefaultDeny, counterValue)
		})
	}
}

func TestUpdateCIDRPolicyModeToNode(t *testing.T) {
	type testCase struct {
		name         string
		policyMode   string
		expectedMode string
	}
	var tests []testCase
	for _, mode := range defaultCIDRPolicies {
		tests = append(tests, testCase{
			name:         fmt.Sprintf("CIDR policy %s mode", mode),
			policyMode:   mode,
			expectedMode: mode,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
				PolicyCIDRMatchMode:    []string{tt.policyMode},
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			// Check that only the expected mode's counter is incremented
			for _, mode := range defaultCIDRPolicies {
				counter, err := metrics.NPCIDRPoliciesToNodes.GetMetricWithLabelValues(mode)
				assert.NoError(t, err)

				counterValue := counter.Get()
				if mode == tt.expectedMode {
					assert.Equal(t, float64(1), counterValue, "Expected mode %s to be incremented", mode)
				} else {
					assert.Equal(t, float64(0), counterValue, "Expected mode %s to remain at 0", mode)
				}
			}
		})
	}
}

func TestUpdateEncryptionMode(t *testing.T) {
	tests := []struct {
		name                      string
		enableIPSec               bool
		enableWireguard           bool
		enableNode2NodeEncryption bool

		expectEncryptionMode      string
		expectNode2NodeEncryption string
	}{
		{
			name:                      "IPSec enabled",
			enableIPSec:               true,
			expectEncryptionMode:      advConnNetEncIPSec,
			expectNode2NodeEncryption: "false",
		},
		{
			name:                      "IPSec disabled",
			enableIPSec:               false,
			expectEncryptionMode:      "",
			expectNode2NodeEncryption: "",
		},
		{
			name:                      "IPSec enabled w/ node2node",
			enableIPSec:               true,
			enableNode2NodeEncryption: true,
			expectEncryptionMode:      advConnNetEncIPSec,
			expectNode2NodeEncryption: "true",
		},
		{
			name:                      "Wireguard enabled",
			enableWireguard:           true,
			expectEncryptionMode:      advConnNetEncWireGuard,
			expectNode2NodeEncryption: "false",
		},
		{
			name:                      "Wireguard enabled w/ node2node",
			enableWireguard:           true,
			enableNode2NodeEncryption: true,
			expectEncryptionMode:      advConnNetEncWireGuard,
			expectNode2NodeEncryption: "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
				EnableIPSec:            tt.enableIPSec,
				EnableWireguard:        tt.enableWireguard,
				EncryptNode:            tt.enableNode2NodeEncryption,
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			// Check that only the expected mode's counter is incremented
			for _, encMode := range defaultEncryptionModes {
				for _, node2node := range []string{"true", "false"} {
					counter, err := metrics.ACLBTransparentEncryption.GetMetricWithLabelValues(encMode, node2node)
					assert.NoError(t, err)

					counterValue := counter.Get()
					if encMode == tt.expectEncryptionMode && node2node == tt.expectNode2NodeEncryption {
						assert.Equal(t, float64(1), counterValue, "Expected mode %s to be incremented", encMode)
					} else {
						assert.Equal(t, float64(0), counterValue, "Expected mode %s to remain at 0", encMode)
					}
				}
			}
		})
	}
}

func TestUpdateKubeProxyReplacement(t *testing.T) {
	tests := []struct {
		name                       string
		enableKubeProxyReplacement string
		expected                   float64
	}{
		{
			name:                       "KubeProxyReplacement enabled",
			enableKubeProxyReplacement: "true",
			expected:                   1,
		},
		{
			name:                       "KubeProxyReplacement disabled",
			enableKubeProxyReplacement: "false",
			expected:                   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
				KubeProxyReplacement:   tt.enableKubeProxyReplacement,
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.ACLBKubeProxyReplacementEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableKubeProxyReplacement, counterValue)
		})
	}
}

func TestUpdateNodePortConfig(t *testing.T) {
	type testCase struct {
		name             string
		portMode         string
		algoMode         string
		accelerationMode string

		expectedPortMode         string
		expectedAlgoMode         string
		expectedAccelerationMode string
	}
	var tests []testCase
	for _, portMode := range defaultNodePortModes {
		for _, algoMode := range defaultNodePortModeAlgorithms {
			for _, aclMode := range defaultNodePortModeAccelerations {
				tests = append(tests, testCase{
					name:             fmt.Sprintf("NodePortConfig %s - %s - %s", portMode, algoMode, aclMode),
					portMode:         portMode,
					algoMode:         algoMode,
					accelerationMode: aclMode,

					expectedPortMode:         portMode,
					expectedAlgoMode:         algoMode,
					expectedAccelerationMode: aclMode,
				})
			}
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   tt.accelerationMode,
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = tt.algoMode
			lbConfig.LBMode = tt.portMode

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			// Check that only the expected mode's counter is incremented
			for _, portMode := range defaultNodePortModes {
				for _, algoMode := range defaultNodePortModeAlgorithms {
					for _, aclMode := range defaultNodePortModeAccelerations {
						counter, err := metrics.ACLBNodePortConfig.GetMetricWithLabelValues(portMode, algoMode, aclMode)
						assert.NoError(t, err)

						counterValue := counter.Get()
						if portMode == tt.expectedPortMode &&
							algoMode == tt.expectedAlgoMode &&
							aclMode == tt.expectedAccelerationMode {
							assert.Equal(t, float64(1), counterValue, "Expected mode %s - %s - %s to be incremented", portMode, algoMode, aclMode)
						} else {
							assert.Equal(t, float64(0), counterValue, "Expected mode %s - %s - %s to remain at 0", portMode, algoMode, aclMode)
						}
					}
				}
			}
		})
	}
}

func TestUpdateBGP(t *testing.T) {
	tests := []struct {
		name            string
		bgpControlPlane bool
		expected        float64
	}{
		{
			name:            "Enable BGP Control Plane",
			bgpControlPlane: true,
			expected:        1,
		},
		{
			name:     "BGP disabled",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
				EnableBGPControlPlane:  tt.bgpControlPlane,
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.ACLBBGPEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for bgpControlPlane: %t, got %.f", tt.expected, tt.bgpControlPlane, counterValue)
		})
	}
}

func TestUpdateIPv4EgressGateway(t *testing.T) {
	tests := []struct {
		name      string
		enableEGW bool
		expected  float64
	}{
		{
			name:      "Enable EGW",
			enableEGW: true,
			expected:  1,
		},
		{
			name:      "Disable EGW",
			enableEGW: false,
			expected:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                    defaultIPAMModes[0],
				EnableIPv4:              true,
				IdentityAllocationMode:  defaultIdentityAllocationModes[0],
				DatapathMode:            defaultDeviceModes[0],
				NodePortAcceleration:    defaultNodePortModeAccelerations[0],
				EnableIPv4EgressGateway: tt.enableEGW,
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.ACLBEgressGatewayEnabled.Get()

			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableEGW, counterValue)
		})
	}
}

func TestUpdateBandwidthManager(t *testing.T) {
	tests := []struct {
		name                   string
		enableBandwidthManager bool
		expected               float64
	}{
		{
			name:                   "BandwidthManager enabled",
			enableBandwidthManager: true,
			expected:               1,
		},
		{
			name:                   "BandwidthManager disabled",
			enableBandwidthManager: false,
			expected:               0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode:  defaultChainingModes[0],
				BandwidthManager: tt.enableBandwidthManager,
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.ACLBBandwidthManagerEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableBandwidthManager, counterValue)
		})
	}
}

func TestUpdateSCTP(t *testing.T) {
	tests := []struct {
		name       string
		enableSCTP bool
		expected   float64
	}{
		{
			name:       "SCTP enabled",
			enableSCTP: true,
			expected:   1,
		},
		{
			name:       "SCTP disabled",
			enableSCTP: false,
			expected:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				EnableSCTP:             tt.enableSCTP,
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.ACLBSCTPEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableSCTP, counterValue)
		})
	}
}

func TestUpdateInternalTrafficPolicy(t *testing.T) {
	tests := []struct {
		name                        string
		enableInternalTrafficPolicy bool
		expected                    float64
	}{
		{
			name:                        "InternalTrafficPolicy enabled",
			enableInternalTrafficPolicy: true,
			expected:                    1,
		},
		{
			name:                        "InternalTrafficPolicy disabled",
			enableInternalTrafficPolicy: false,
			expected:                    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				EnableInternalTrafficPolicy: tt.enableInternalTrafficPolicy,
				IPAM:                        defaultIPAMModes[0],
				EnableIPv4:                  true,
				IdentityAllocationMode:      defaultIdentityAllocationModes[0],
				DatapathMode:                defaultDeviceModes[0],
				NodePortAcceleration:        defaultNodePortModeAccelerations[0],
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.ACLBInternalTrafficPolicyEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableInternalTrafficPolicy, counterValue)
		})
	}
}

func TestUpdateVTEP(t *testing.T) {
	tests := []struct {
		name       string
		enableVTEP bool
		expected   float64
	}{
		{
			name:       "VTEP enabled",
			enableVTEP: true,
			expected:   1,
		},
		{
			name:       "VTEP disabled",
			enableVTEP: false,
			expected:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				EnableVTEP:             tt.enableVTEP,
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.ACLBVTEPEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableVTEP, counterValue)
		})
	}
}

func TestUpdateEnvoyConfig(t *testing.T) {
	tests := []struct {
		name              string
		enableEnvoyConfig bool
		expected          float64
	}{
		{
			name:              "EnvoyConfig enabled",
			enableEnvoyConfig: true,
			expected:          1,
		},
		{
			name:              "EnvoyConfig disabled",
			enableEnvoyConfig: false,
			expected:          0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				EnableEnvoyConfig:      tt.enableEnvoyConfig,
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.ACLBCiliumEnvoyConfigEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableEnvoyConfig, counterValue)
		})
	}
}

func TestUpdateBigTCPProtocol(t *testing.T) {
	tests := []struct {
		name             string
		enableIPv4       bool
		enableIPv6       bool
		expectedProtocol string
	}{
		{
			name:             "IPv4-only",
			enableIPv4:       true,
			expectedProtocol: advConnBigTCPIPv4,
		},
		{
			name:             "IPv6-only",
			enableIPv6:       true,
			expectedProtocol: advConnBigTCPIPv6,
		},
		{
			name:             "IPv4-IPv6-dual-stack",
			enableIPv4:       true,
			enableIPv6:       true,
			expectedProtocol: advConnBigTCPDualStack,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
				EnableIPv4:             true,
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
				bigTCPMock: bigTCPMock{
					ipv4Enabled: tt.enableIPv4,
					ipv6Enabled: tt.enableIPv6,
				},
			}

			metrics.update(params, config, lbConfig)

			// Check that only the expected mode's counter is incremented
			for _, mode := range defaultBigTCPAddressFamilies {
				counter, err := metrics.ACLBBigTCPEnabled.GetMetricWithLabelValues(mode)
				assert.NoError(t, err)

				counterValue := counter.Get()
				if mode == tt.expectedProtocol {
					assert.Equal(t, float64(1), counterValue, "Expected mode %s to be incremented", mode)
				} else {
					assert.Equal(t, float64(0), counterValue, "Expected mode %s to remain at 0", mode)
				}
			}
		})
	}
}

func TestUpdateL2Announcements(t *testing.T) {
	tests := []struct {
		name                  string
		enableL2Announcements bool
		expected              float64
	}{
		{
			name:                  "L2Announcements enabled",
			enableL2Announcements: true,
			expected:              1,
		},
		{
			name:                  "L2Announcements disabled",
			enableL2Announcements: false,
			expected:              0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				EnableL2Announcements:  tt.enableL2Announcements,
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.ACLBL2LBEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableL2Announcements, counterValue)
		})
	}
}

func TestUpdateL2PodAnnouncements(t *testing.T) {
	tests := []struct {
		name                     string
		enableL2PodAnnouncements bool
		expected                 float64
	}{
		{
			name:                     "L2Announcements enabled",
			enableL2PodAnnouncements: true,
			expected:                 1,
		},
		{
			name:                     "L2Announcements disabled",
			enableL2PodAnnouncements: false,
			expected:                 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode:   defaultChainingModes[0],
				L2PodAnnouncement: tt.enableL2PodAnnouncements,
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.ACLBL2PodAnnouncementEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableL2PodAnnouncements, counterValue)
		})
	}
}

func TestUpdateExtEnvoyProxyMode(t *testing.T) {
	tests := []struct {
		name               string
		externalEnvoyProxy bool
		expectedMode       string
	}{
		{
			name:               "ExtEnvoyProxyMode embedded",
			externalEnvoyProxy: false,
			expectedMode:       advConnExtEnvoyProxyEmbedded,
		},
		{
			name:               "ExtEnvoyProxyMode standalone",
			externalEnvoyProxy: true,
			expectedMode:       advConnExtEnvoyProxyStandalone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				ExternalEnvoyProxy:     tt.externalEnvoyProxy,
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode: defaultChainingModes[0],
			}

			metrics.update(params, config, lbConfig)

			// Check that only the expected mode's counter is incremented
			for _, mode := range defaultExternalEnvoyProxyModes {
				counter, err := metrics.ACLBExternalEnvoyProxyEnabled.GetMetricWithLabelValues(mode)
				assert.NoError(t, err)

				counterValue := counter.Get()
				if mode == tt.expectedMode {
					assert.Equal(t, float64(1), counterValue, "Expected mode %s to be incremented", mode)
				} else {
					assert.Equal(t, float64(0), counterValue, "Expected mode %s to remain at 0", mode)
				}
			}
		})
	}
}

func TestUpdateDynamicNodeConfig(t *testing.T) {
	tests := []struct {
		name                    string
		enableDynamicNodeConfig bool
		expected                float64
	}{
		{
			name:                    "DynamicNodeConfig enabled",
			enableDynamicNodeConfig: true,
			expected:                1,
		},
		{
			name:                    "DynamicNodeConfig disabled",
			enableDynamicNodeConfig: false,
			expected:                0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{
				IPAM:                   defaultIPAMModes[0],
				EnableIPv4:             true,
				IdentityAllocationMode: defaultIdentityAllocationModes[0],
				DatapathMode:           defaultDeviceModes[0],
				NodePortAcceleration:   defaultNodePortModeAccelerations[0],
			}

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBAlgorithm = defaultNodePortModeAlgorithms[0]
			lbConfig.LBMode = defaultNodePortModes[0]

			params := mockFeaturesParams{
				CNIChainingMode:                     defaultChainingModes[0],
				isDynamicConfigSourceKindNodeConfig: tt.enableDynamicNodeConfig,
			}

			metrics.update(params, config, lbConfig)

			counterValue := metrics.ACLBCiliumNodeConfigEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableDynamicNodeConfig, counterValue)
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

type KPRSuite struct{}

type kprConfig struct {
	kubeProxyReplacement bool

	enableSocketLB             bool
	enableNodePort             bool
	enableIPSec                bool
	enableHostLegacyRouting    bool
	installNoConntrackIptRules bool
	enableBPFMasquerade        bool
	enableIPv4Masquerade       bool
	enableSocketLBTracing      bool

	expectedErrorRegex string

	routingMode    string
	tunnelProtocol tunnel.EncapProtocol
	nodePortMode   string
	dispatchMode   string

	lbConfig  loadbalancer.Config
	kprConfig kpr.KPRConfig
}

func (cfg *kprConfig) set() (err error) {
	cfg.lbConfig = loadbalancer.DefaultConfig

	kprFlags := kpr.KPRFlags{
		KubeProxyReplacement: cfg.kubeProxyReplacement,
		EnableNodePort:       cfg.enableNodePort,
		EnableSocketLB:       cfg.enableSocketLB,
	}

	cfg.kprConfig, err = kpr.NewKPRConfig(kprFlags)
	if err != nil {
		return err
	}

	option.Config.EnableIPSec = cfg.enableIPSec
	option.Config.EnableHostLegacyRouting = cfg.enableHostLegacyRouting
	option.Config.InstallNoConntrackIptRules = cfg.installNoConntrackIptRules
	option.Config.EnableBPFMasquerade = cfg.enableBPFMasquerade
	option.Config.EnableIPv4Masquerade = cfg.enableIPv4Masquerade
	option.Config.EnableSocketLBTracing = true
	option.Config.RoutingMode = cfg.routingMode

	if cfg.nodePortMode == loadbalancer.LBModeDSR || cfg.nodePortMode == loadbalancer.LBModeHybrid {
		cfg.lbConfig.LBMode = cfg.nodePortMode
	}

	cfg.lbConfig.DSRDispatch = cfg.dispatchMode

	return nil
}

func errorMatch(err error, regex string) assert.Comparison {
	return func() (success bool) {
		if err == nil {
			return false
		}

		matched, matchErr := regexp.MatchString(regex, err.Error())
		if matchErr != nil {
			return false
		}
		return matched
	}
}

func (cfg *kprConfig) verify(t *testing.T, lbConfig loadbalancer.Config, kprCfg kpr.KPRConfig, tc tunnel.Config, wgCfg wgTypes.WireguardConfig) {
	logger := hivetest.Logger(t)
	err := initKubeProxyReplacementOptions(logger, sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"), tc, lbConfig, kprCfg, wgCfg)
	if err != nil || cfg.expectedErrorRegex != "" {
		t.Logf("err=%s, expected=%s, cfg=%+v", err, cfg.expectedErrorRegex, cfg)
		require.Condition(t, errorMatch(err, cfg.expectedErrorRegex))
		if strings.Contains(cfg.expectedErrorRegex, "Invalid") {
			return
		}
	}
	require.Equal(t, cfg.enableSocketLB, kprCfg.EnableSocketLB)
	require.Equal(t, cfg.enableNodePort, kprCfg.EnableNodePort)
	require.Equal(t, cfg.enableIPSec, option.Config.EnableIPSec)
	require.Equal(t, cfg.enableHostLegacyRouting, option.Config.EnableHostLegacyRouting)
	require.Equal(t, cfg.installNoConntrackIptRules, option.Config.InstallNoConntrackIptRules)
	require.Equal(t, cfg.enableBPFMasquerade, option.Config.EnableBPFMasquerade)
	require.Equal(t, cfg.enableIPv4Masquerade, option.Config.EnableIPv4Masquerade)
	require.Equal(t, cfg.enableSocketLBTracing, option.Config.EnableSocketLBTracing)
}

func setupKPRSuite(tb testing.TB) *KPRSuite {
	s := &KPRSuite{}

	mockCmd := &cobra.Command{}
	h := hive.New(Agent)
	h.RegisterFlags(mockCmd.Flags())
	logger := hivetest.Logger(tb)
	InitGlobalFlags(logger, mockCmd, h.Viper())
	option.Config.Populate(logger, h.Viper())
	option.Config.DryMode = true

	return s
}

func TestInitKubeProxyReplacementOptions(t *testing.T) {
	setupKPRSuite(t)

	cases := []struct {
		name string
		mod  func(*kprConfig)
		out  kprConfig
	}{
		// KPR true: all options enabled, host routing disabled.
		{
			"kpr-true",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
			},
			kprConfig{
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
			},
		},

		// KPR true + IPsec: all options enabled, host routing disabled.
		{
			"kpr-true+ipsec",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.enableIPSec = true
			},
			kprConfig{
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostLegacyRouting: false,
				enableIPSec:             true,
				enableSocketLBTracing:   true,
			},
		},

		// KPR true + no conntrack ipt rules + masquerade: ok
		{
			"kpr-true+no-conntrack-ipt-rules+masquerade",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.installNoConntrackIptRules = true
				cfg.enableBPFMasquerade = true
				cfg.enableIPv4Masquerade = true
			},
			kprConfig{
				enableSocketLB:             true,
				enableNodePort:             true,
				enableHostLegacyRouting:    false,
				enableBPFMasquerade:        true,
				enableIPv4Masquerade:       true,
				installNoConntrackIptRules: true,
				enableSocketLBTracing:      true,
			},
		},

		// KPR true + no conntrack ipt rules: error, needs bpf masquerade
		{
			"kpr-true+no-conntrack-ipt-rules+no-bpf-masquerade",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.installNoConntrackIptRules = true
				cfg.enableIPv4Masquerade = true
			},
			kprConfig{
				expectedErrorRegex:         ".+with enable-bpf-masquerade.",
				enableSocketLB:             true,
				enableNodePort:             true,
				enableHostLegacyRouting:    false,
				installNoConntrackIptRules: true,
				enableIPv4Masquerade:       true,
				enableSocketLBTracing:      true,
			},
		},

		// KPR false: all options disabled
		{
			"kpr-disabled",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = false
			},
			kprConfig{
				enableSocketLB:          false,
				enableNodePort:          false,
				enableIPSec:             false,
				enableHostLegacyRouting: true,
				enableSocketLBTracing:   false,
				expectedErrorRegex:      "",
			},
		},

		// KPR false + no conntrack ipt rules: error, needs KPR
		{
			"kpr-false+no-conntrack-ipt-rules",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = false
				cfg.installNoConntrackIptRules = true
				cfg.enableNodePort = true
			},
			kprConfig{
				expectedErrorRegex:         ".+with kube-proxy-replacement.",
				enableSocketLB:             false,
				enableNodePort:             true,
				enableHostLegacyRouting:    false,
				installNoConntrackIptRules: true,
				enableSocketLBTracing:      true,
			},
		},
		// Node port DSR mode + vxlan tunneling: error as they're incompatible
		{
			"node-port-dsr-mode+vxlan",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.routingMode = option.RoutingModeTunnel
				cfg.tunnelProtocol = tunnel.VXLAN
				cfg.nodePortMode = loadbalancer.LBModeDSR
				cfg.dispatchMode = loadbalancer.DSRDispatchOption
			},
			kprConfig{
				expectedErrorRegex:      "Node Port .+ mode cannot be used with .+ tunneling.",
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
			},
		},

		// Node port DSR mode + Geneve dispatch + native routing
		{
			"node-port-dsr-mode+geneve-dispatch+native-routing",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.routingMode = option.RoutingModeNative
				cfg.tunnelProtocol = tunnel.Geneve
				cfg.nodePortMode = loadbalancer.LBModeDSR
				cfg.dispatchMode = loadbalancer.DSRDispatchGeneve
			},
			kprConfig{
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
			},
		},
		// Node port DSR mode + Geneve dispatch + geneve routing
		{
			"node-port-dsr-mode+geneve-dispatch+geneve-routing",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.routingMode = option.RoutingModeTunnel
				cfg.tunnelProtocol = tunnel.Geneve
				cfg.nodePortMode = loadbalancer.LBModeDSR
				cfg.dispatchMode = loadbalancer.DSRDispatchGeneve
			},
			kprConfig{
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
			},
		},
		// Node port DSR mode + Geneve dispatch + vxlan routing: error as they're incompatible
		{
			"node-port-dsr-mode+geneve-dispatch+vxlan-routing",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.routingMode = option.RoutingModeTunnel
				cfg.tunnelProtocol = tunnel.VXLAN
				cfg.nodePortMode = loadbalancer.LBModeDSR
				cfg.dispatchMode = loadbalancer.DSRDispatchGeneve
			},
			kprConfig{
				expectedErrorRegex:      "Node Port .+ mode cannot be used with .+ tunneling.",
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
			},
		},

		// Node port Hybrid mode + Geneve dispatch + native routing
		{
			"node-port-hybrid-mode+geneve-dispatch+native-routing",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.routingMode = option.RoutingModeNative
				cfg.tunnelProtocol = tunnel.Geneve
				cfg.nodePortMode = loadbalancer.LBModeHybrid
				cfg.dispatchMode = loadbalancer.DSRDispatchGeneve
			},
			kprConfig{
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
			},
		},
		// Node port Hybrid mode + Geneve dispatch + geneve routing
		{
			"node-port-hybrid-mode+geneve-dispatch+geneve-routing",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.routingMode = option.RoutingModeTunnel
				cfg.tunnelProtocol = tunnel.Geneve
				cfg.nodePortMode = loadbalancer.LBModeHybrid
				cfg.dispatchMode = loadbalancer.DSRDispatchGeneve
			},
			kprConfig{
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
			},
		},
		// Node port Hybrid mode + Geneve dispatch + vxlan routing: error as they're incompatible
		{
			"node-port-hybrid-mode+geneve-dispatch+vxlan-routing",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.routingMode = option.RoutingModeTunnel
				cfg.tunnelProtocol = tunnel.VXLAN
				cfg.nodePortMode = loadbalancer.LBModeHybrid
				cfg.dispatchMode = loadbalancer.DSRDispatchGeneve
			},
			kprConfig{
				expectedErrorRegex:      "Node Port .+ mode cannot be used with .+ tunneling.",
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
			},
		},
	}

	def := kprConfig{}

	for _, testCase := range cases {
		t.Logf("Testing %s", testCase.name)
		cfg := def
		testCase.mod(&cfg)
		require.NoError(t, cfg.set())
		testCase.out.verify(t, cfg.lbConfig, cfg.kprConfig, tunnel.NewTestConfig(cfg.tunnelProtocol), fakeTypes.WireguardConfig{})
		def.set()
	}
}

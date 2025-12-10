// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package initializer

import (
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/fake/types"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

type kprConfig struct {
	kubeProxyReplacement bool

	enableSocketLB             bool
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

	lbConfig    loadbalancer.Config
	kprConfig   kpr.KPRConfig
	ipsecConfig types.IPsecConfig
}

func (cfg *kprConfig) set() (err error) {
	cfg.lbConfig = loadbalancer.DefaultConfig

	kprFlags := kpr.KPRFlags{
		KubeProxyReplacement: cfg.kubeProxyReplacement,
		EnableSocketLB:       cfg.enableSocketLB,
	}

	cfg.kprConfig, err = kpr.NewKPRConfig(kprFlags)
	if err != nil {
		return err
	}

	cfg.ipsecConfig = fakeTypes.IPsecConfig{EnableIPsec: cfg.enableIPSec}
	option.Config.UnsafeDaemonConfigOption.EnableHostLegacyRouting = cfg.enableHostLegacyRouting
	option.Config.InstallNoConntrackIptRules = cfg.installNoConntrackIptRules
	option.Config.EnableBPFMasquerade = cfg.enableBPFMasquerade
	option.Config.EnableIPv4Masquerade = cfg.enableIPv4Masquerade
	option.Config.UnsafeDaemonConfigOption.EnableSocketLBTracing = true
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
	kprManager := &kprInitializer{
		logger:       logger,
		sysctl:       sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
		tunnelConfig: tc,
		lbConfig:     lbConfig,
		kprCfg:       kprCfg,
		wgCfg:        wgCfg,
	}
	err := kprManager.InitKubeProxyReplacementOptions()
	if err != nil || cfg.expectedErrorRegex != "" {
		t.Logf("err=%s, expected=%s, cfg=%+v", err, cfg.expectedErrorRegex, cfg)
		require.Condition(t, errorMatch(err, cfg.expectedErrorRegex))
		if strings.Contains(cfg.expectedErrorRegex, "Invalid") {
			return
		}
	}
	require.Equal(t, cfg.enableSocketLB, kprCfg.EnableSocketLB)
	require.Equal(t, cfg.enableHostLegacyRouting, option.Config.UnsafeDaemonConfigOption.EnableHostLegacyRouting)
	require.Equal(t, cfg.installNoConntrackIptRules, option.Config.InstallNoConntrackIptRules)
	require.Equal(t, cfg.enableBPFMasquerade, option.Config.EnableBPFMasquerade)
	require.Equal(t, cfg.enableIPv4Masquerade, option.Config.EnableIPv4Masquerade)
	require.Equal(t, cfg.enableSocketLBTracing, option.Config.UnsafeDaemonConfigOption.EnableSocketLBTracing)
}

func TestInitKubeProxyReplacementOptions(t *testing.T) {
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
				enableHostLegacyRouting:    true,
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
			},
			kprConfig{
				expectedErrorRegex:         ".+with kube-proxy-replacement.",
				enableSocketLB:             false,
				enableHostLegacyRouting:    true,
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

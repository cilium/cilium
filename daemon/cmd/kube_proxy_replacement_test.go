// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"strings"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/option"
)

type KPRSuite struct{}

var _ = Suite(&KPRSuite{})

type kprConfig struct {
	kubeProxyReplacement string

	enableSocketLB             bool
	enableNodePort             bool
	enableHostPort             bool
	enableExternalIPs          bool
	enableSessionAffinity      bool
	enableIPSec                bool
	enableHostLegacyRouting    bool
	installNoConntrackIptRules bool
	enableBPFMasquerade        bool
	enableIPv4Masquerade       bool
	enableSocketLBTracing      bool

	expectedErrorRegex string

	routingMode    string
	tunnelProtocol string
	nodePortMode   string
}

func (cfg *kprConfig) set() {
	option.Config.KubeProxyReplacement = cfg.kubeProxyReplacement
	option.Config.EnableSocketLB = cfg.enableSocketLB
	option.Config.EnableNodePort = cfg.enableNodePort
	option.Config.EnableHostPort = cfg.enableHostPort
	option.Config.EnableExternalIPs = cfg.enableExternalIPs
	option.Config.EnableSessionAffinity = cfg.enableSessionAffinity
	option.Config.EnableIPSec = cfg.enableIPSec
	option.Config.EnableHostLegacyRouting = cfg.enableHostLegacyRouting
	option.Config.InstallNoConntrackIptRules = cfg.installNoConntrackIptRules
	option.Config.EnableBPFMasquerade = cfg.enableBPFMasquerade
	option.Config.EnableIPv4Masquerade = cfg.enableIPv4Masquerade
	option.Config.EnableSocketLBTracing = true
	option.Config.RoutingMode = cfg.routingMode
	option.Config.TunnelProtocol = cfg.tunnelProtocol

	if cfg.nodePortMode == option.NodePortModeDSR || cfg.nodePortMode == option.NodePortModeHybrid {
		option.Config.NodePortMode = cfg.nodePortMode
	}
}

func (cfg *kprConfig) verify(c *C) {
	err := initKubeProxyReplacementOptions()
	if err != nil || cfg.expectedErrorRegex != "" {
		c.Assert(err, ErrorMatches, cfg.expectedErrorRegex)
		if strings.Contains(cfg.expectedErrorRegex, "Invalid") {
			return
		}
	}

	c.Assert(option.Config.EnableSocketLB, Equals, cfg.enableSocketLB)
	c.Assert(option.Config.EnableNodePort, Equals, cfg.enableNodePort)
	c.Assert(option.Config.EnableHostPort, Equals, cfg.enableHostPort)
	c.Assert(option.Config.EnableExternalIPs, Equals, cfg.enableExternalIPs)
	c.Assert(option.Config.EnableSessionAffinity, Equals, cfg.enableSessionAffinity)
	c.Assert(option.Config.EnableIPSec, Equals, cfg.enableIPSec)
	c.Assert(option.Config.EnableHostLegacyRouting, Equals, cfg.enableHostLegacyRouting)
	c.Assert(option.Config.InstallNoConntrackIptRules, Equals, cfg.installNoConntrackIptRules)
	c.Assert(option.Config.EnableBPFMasquerade, Equals, cfg.enableBPFMasquerade)
	c.Assert(option.Config.EnableIPv4Masquerade, Equals, cfg.enableIPv4Masquerade)
	c.Assert(option.Config.EnableSocketLBTracing, Equals, cfg.enableSocketLBTracing)
}

func (s *KPRSuite) SetUpTest(c *C) {
	option.Config.Populate(Vp)
	option.Config.DryMode = true
}

func (s *KPRSuite) TestInitKubeProxyReplacementOptions(c *C) {
	cases := []struct {
		name string
		mod  func(*kprConfig)
		out  kprConfig
	}{
		// Invalid value for kube-proxy-replacement yields error
		{
			"invalid-value",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = "invalid value"
			},
			kprConfig{
				kubeProxyReplacement: "invalid value",
				expectedErrorRegex:   "Invalid value.+",
			},
		},

		// KPR disabled: all options disabled except host legacy routing.
		{
			"kpr-disabled",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = option.KubeProxyReplacementDisabled
			},
			kprConfig{
				enableSocketLB:          false,
				enableNodePort:          false,
				enableHostPort:          false,
				enableExternalIPs:       false,
				enableSessionAffinity:   false,
				enableIPSec:             false,
				enableHostLegacyRouting: true,
				enableSocketLBTracing:   false,
				expectedErrorRegex:      "",
			},
		},

		// KPR strict: all options enabled, host routing disabled.
		{
			"kpr-strict",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = option.KubeProxyReplacementStrict
			},
			kprConfig{
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostPort:          true,
				enableExternalIPs:       true,
				enableSessionAffinity:   true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
			},
		},

		// KPR strict + IPsec: error as they're incompatible
		{
			"kpr-strict+ipsec",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = option.KubeProxyReplacementStrict
				cfg.enableIPSec = true
			},
			kprConfig{
				expectedErrorRegex: "IPSec cannot be used with.+",
				// options are still left enabled:
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostPort:          true,
				enableExternalIPs:       true,
				enableSessionAffinity:   true,
				enableHostLegacyRouting: false,
				enableIPSec:             true,
				enableSocketLBTracing:   true,
			},
		},

		// KPR strict + no conntrack ipt rules + masquerade: ok
		{
			"kpr-strict+no-conntrack-ipt-rules+masquerade",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = option.KubeProxyReplacementStrict
				cfg.installNoConntrackIptRules = true
				cfg.enableBPFMasquerade = true
				cfg.enableIPv4Masquerade = true
			},
			kprConfig{
				enableSocketLB:             true,
				enableNodePort:             true,
				enableHostPort:             true,
				enableExternalIPs:          true,
				enableSessionAffinity:      true,
				enableHostLegacyRouting:    false,
				enableBPFMasquerade:        true,
				enableIPv4Masquerade:       true,
				installNoConntrackIptRules: true,
				enableSocketLBTracing:      true,
			},
		},

		// KPR strict + no conntrack ipt rules: error, needs bpf masquerade
		{
			"kpr-strict+no-conntrack-ipt-rules+no-bpf-masquerade",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = option.KubeProxyReplacementStrict
				cfg.installNoConntrackIptRules = true
				cfg.enableIPv4Masquerade = true
			},
			kprConfig{
				expectedErrorRegex:         ".+with enable-bpf-masquerade.",
				enableSocketLB:             true,
				enableNodePort:             true,
				enableHostPort:             true,
				enableExternalIPs:          true,
				enableSessionAffinity:      true,
				enableHostLegacyRouting:    false,
				installNoConntrackIptRules: true,
				enableIPv4Masquerade:       true,
				enableSocketLBTracing:      true,
			},
		},
		// KPR partial + no conntrack ipt rules: error, needs KPR
		{
			"kpr-partial+no-conntrack-ipt-rules",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = option.KubeProxyReplacementPartial
				cfg.installNoConntrackIptRules = true
				cfg.enableNodePort = true
			},
			kprConfig{
				expectedErrorRegex:         ".+with kube-proxy-replacement=strict.",
				enableSocketLB:             false,
				enableNodePort:             true,
				enableHostPort:             false,
				enableExternalIPs:          false,
				enableSessionAffinity:      false,
				enableHostLegacyRouting:    false,
				installNoConntrackIptRules: true,
				enableSocketLBTracing:      true,
			},
		},
		// Node port DSR mode + vxlan tunneling: error as they're incompatible
		{
			"node-port-dsr-mode+vxlan",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = option.KubeProxyReplacementStrict
				cfg.routingMode = option.RoutingModeTunnel
				cfg.tunnelProtocol = option.TunnelVXLAN
				cfg.nodePortMode = option.NodePortModeDSR
			},
			kprConfig{
				expectedErrorRegex:      "Node Port .+ mode cannot be used with .+ tunneling.",
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostPort:          true,
				enableExternalIPs:       true,
				enableSessionAffinity:   true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
			},
		},
	}

	def := kprConfig{}

	for _, testCase := range cases {
		c.Logf("Testing %s", testCase.name)
		cfg := def
		testCase.mod(&cfg)
		cfg.set()
		testCase.out.verify(c)
		def.set()
	}
}

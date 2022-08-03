// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"strings"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/option"
)

type KPRSuite struct {
	orig kprConfig
}

var _ = Suite(&KPRSuite{})

type kprConfig struct {
	kubeProxyReplacement string

	enableSocketLB                               bool
	enableNodePort                               bool
	enableHostPort                               bool
	enableExternalIPs                            bool
	enableHostServicesTCP, enableHostServicesUDP bool
	enableSessionAffinity                        bool
	enableIPSec                                  bool
	enableHostLegacyRouting                      bool
	installNoConntrackIptRules                   bool
	enableBPFMasquerade                          bool
	enableIPv4Masquerade                         bool
	enableSocketLBTracing                        bool

	expectedStrict     bool
	expectedErrorRegex string
}

func (cfg *kprConfig) set() {
	option.Config.KubeProxyReplacement = cfg.kubeProxyReplacement
	option.Config.EnableSocketLB = cfg.enableSocketLB
	option.Config.EnableNodePort = cfg.enableNodePort
	option.Config.EnableHostPort = cfg.enableHostPort
	option.Config.EnableExternalIPs = cfg.enableExternalIPs
	option.Config.EnableHostServicesTCP = cfg.enableHostServicesTCP
	option.Config.EnableHostServicesUDP = cfg.enableHostServicesUDP
	option.Config.EnableSessionAffinity = cfg.enableSessionAffinity
	option.Config.EnableIPSec = cfg.enableIPSec
	option.Config.EnableHostLegacyRouting = cfg.enableHostLegacyRouting
	option.Config.InstallNoConntrackIptRules = cfg.installNoConntrackIptRules
	option.Config.EnableBPFMasquerade = cfg.enableBPFMasquerade
	option.Config.EnableIPv4Masquerade = cfg.enableIPv4Masquerade
	option.Config.EnableSocketLBTracing = true
}

func (cfg *kprConfig) read() {
	cfg.kubeProxyReplacement = option.Config.KubeProxyReplacement
	cfg.enableSocketLB = option.Config.EnableSocketLB
	cfg.enableNodePort = option.Config.EnableNodePort
	cfg.enableHostPort = option.Config.EnableHostPort
	cfg.enableExternalIPs = option.Config.EnableExternalIPs
	cfg.enableHostServicesTCP = option.Config.EnableHostServicesTCP
	cfg.enableHostServicesUDP = option.Config.EnableHostServicesUDP
	cfg.enableSessionAffinity = option.Config.EnableSessionAffinity
	cfg.enableIPSec = option.Config.EnableIPSec
	cfg.enableHostLegacyRouting = option.Config.EnableHostLegacyRouting
	cfg.installNoConntrackIptRules = option.Config.InstallNoConntrackIptRules
	cfg.enableBPFMasquerade = option.Config.EnableBPFMasquerade
	cfg.enableIPv4Masquerade = option.Config.EnableIPv4Masquerade
	cfg.enableSocketLBTracing = option.Config.EnableSocketLBTracing
}

func (cfg *kprConfig) verify(c *C) {
	strict, err := initKubeProxyReplacementOptions()

	if err != nil || cfg.expectedErrorRegex != "" {
		c.Assert(err, ErrorMatches, cfg.expectedErrorRegex)
		if strings.Contains(cfg.expectedErrorRegex, "Invalid") {
			return
		}
	}
	c.Assert(strict, Equals, cfg.expectedStrict)

	c.Assert(option.Config.EnableSocketLB, Equals, cfg.enableSocketLB)
	c.Assert(option.Config.EnableNodePort, Equals, cfg.enableNodePort)
	c.Assert(option.Config.EnableHostPort, Equals, cfg.enableHostPort)
	c.Assert(option.Config.EnableExternalIPs, Equals, cfg.enableExternalIPs)
	c.Assert(option.Config.EnableHostServicesTCP, Equals, cfg.enableHostServicesTCP)
	c.Assert(option.Config.EnableHostServicesUDP, Equals, cfg.enableHostServicesUDP)
	c.Assert(option.Config.EnableSessionAffinity, Equals, cfg.enableSessionAffinity)
	c.Assert(option.Config.EnableIPSec, Equals, cfg.enableIPSec)
	c.Assert(option.Config.EnableHostLegacyRouting, Equals, cfg.enableHostLegacyRouting)
	c.Assert(option.Config.InstallNoConntrackIptRules, Equals, cfg.installNoConntrackIptRules)
	c.Assert(option.Config.EnableBPFMasquerade, Equals, cfg.enableBPFMasquerade)
	c.Assert(option.Config.EnableIPv4Masquerade, Equals, cfg.enableIPv4Masquerade)
	c.Assert(option.Config.EnableSocketLBTracing, Equals, cfg.enableSocketLBTracing)
}

func (s *KPRSuite) SetUpTest(c *C) {
	s.orig.read()
}

func (s *KPRSuite) TearDownTest(c *C) {
	s.orig.set()
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
				enableHostServicesTCP:   false,
				enableHostServicesUDP:   false,
				enableSessionAffinity:   false,
				enableIPSec:             false,
				enableHostLegacyRouting: true,
				enableSocketLBTracing:   false,
				expectedStrict:          false,
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
				expectedStrict:          true,
				enableSocketLB:          true,
				enableNodePort:          true,
				enableHostPort:          true,
				enableExternalIPs:       true,
				enableHostServicesTCP:   true,
				enableHostServicesUDP:   true,
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
				enableHostServicesTCP:   true,
				enableHostServicesUDP:   true,
				enableSessionAffinity:   true,
				enableHostLegacyRouting: false,
				enableIPSec:             true,
				enableSocketLBTracing:   true,
			},
		},

		// KPR probe + IPsec: nodeport gets disabled
		{
			"kpr-probe+ipsec",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = option.KubeProxyReplacementProbe
				cfg.enableIPSec = true
			},
			kprConfig{
				enableSocketLB:          true,
				enableNodePort:          false,
				enableHostPort:          false,
				enableExternalIPs:       false,
				enableHostServicesTCP:   true,
				enableHostServicesUDP:   true,
				enableSessionAffinity:   true,
				enableHostLegacyRouting: true,
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
				expectedStrict:             true,
				enableSocketLB:             true,
				enableNodePort:             true,
				enableHostPort:             true,
				enableExternalIPs:          true,
				enableHostServicesTCP:      true,
				enableHostServicesUDP:      true,
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
				enableHostServicesTCP:      true,
				enableHostServicesUDP:      true,
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
				enableHostServicesTCP:      false,
				enableHostServicesUDP:      false,
				enableSessionAffinity:      false,
				enableHostLegacyRouting:    false,
				installNoConntrackIptRules: true,
				enableSocketLBTracing:      true,
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

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package initializer

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	ipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
	wireguard "github.com/cilium/cilium/pkg/wireguard/types"
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
	enableIPIPTermination      bool

	expectedErrorRegex string

	routingMode      string
	tunnelProtocol   tunnel.EncapProtocol
	nodePortMode     string
	dispatchMode     string
	lbModeAnnotation bool

	lbConfig    loadbalancer.Config
	kprConfig   kpr.KPRConfig
	ipsecConfig ipsec.Config
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

	cfg.ipsecConfig = fakeipsec.Config{EnableIPsec: cfg.enableIPSec}
	option.Config.UnsafeDaemonConfigOption.EnableHostLegacyRouting = cfg.enableHostLegacyRouting
	option.Config.InstallNoConntrackIptRules = cfg.installNoConntrackIptRules
	option.Config.EnableBPFMasquerade = cfg.enableBPFMasquerade
	option.Config.EnableIPv4Masquerade = cfg.enableIPv4Masquerade
	option.Config.UnsafeDaemonConfigOption.EnableSocketLBTracing = true
	option.Config.RoutingMode = cfg.routingMode
	option.Config.EnableIPIPTermination = false
	option.Config.UnsafeDaemonConfigOption.EnableIPIPDevices = false

	if cfg.nodePortMode == loadbalancer.LBModeDSR || cfg.nodePortMode == loadbalancer.LBModeHybrid {
		cfg.lbConfig.LBMode = cfg.nodePortMode
	}

	cfg.lbConfig.LBModeAnnotation = cfg.lbModeAnnotation
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

func (cfg *kprConfig) verify(t *testing.T, lbConfig loadbalancer.Config, kprCfg kpr.KPRConfig, tc tunnel.Config, wgCfg wireguard.Config) {
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
	require.Equal(t, cfg.enableIPIPTermination, option.Config.EnableIPIPTermination)
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
		// Node port DSR mode + IPIP dispatch + native routing: IPIP termination
		// is enabled implicitly, without a separate --enable-ipip-termination.
		{
			"node-port-dsr-mode+ipip-dispatch+native-routing",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.routingMode = option.RoutingModeNative
				cfg.nodePortMode = loadbalancer.LBModeDSR
				cfg.dispatchMode = loadbalancer.DSRDispatchIPIP
			},
			kprConfig{
				enableSocketLB:          true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
				enableIPIPTermination:   true,
			},
		},
		// Node port hybrid mode + IPIP dispatch + native routing: hybrid also
		// uses DSR, so IPIP termination is enabled implicitly as well.
		{
			"node-port-hybrid-mode+ipip-dispatch+native-routing",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.routingMode = option.RoutingModeNative
				cfg.nodePortMode = loadbalancer.LBModeHybrid
				cfg.dispatchMode = loadbalancer.DSRDispatchIPIP
			},
			kprConfig{
				enableSocketLB:          true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
				enableIPIPTermination:   true,
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

		// LB mode annotation + IPIP dispatch + vxlan routing: ok, as IPIP
		// dispatch is not mutually exclusive with VXLAN.
		{
			"lb-mode-annotation+ipip-dispatch+vxlan-routing",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.routingMode = option.RoutingModeTunnel
				cfg.tunnelProtocol = tunnel.VXLAN
				cfg.lbModeAnnotation = true
				cfg.dispatchMode = loadbalancer.DSRDispatchIPIP
			},
			kprConfig{
				enableSocketLB:          true,
				enableHostLegacyRouting: false,
				enableSocketLBTracing:   true,
				enableIPIPTermination:   true,
			},
		},
		// LB mode annotation + Geneve dispatch + vxlan routing: error, as only
		// IPIP dispatch is supported with VXLAN tunneling.
		{
			"lb-mode-annotation+geneve-dispatch+vxlan-routing",
			func(cfg *kprConfig) {
				cfg.kubeProxyReplacement = true
				cfg.routingMode = option.RoutingModeTunnel
				cfg.tunnelProtocol = tunnel.VXLAN
				cfg.lbModeAnnotation = true
				cfg.dispatchMode = loadbalancer.DSRDispatchGeneve
			},
			kprConfig{
				expectedErrorRegex:      "Only --.+ is supported with .+ tunneling when --.+ is set",
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
		testCase.out.verify(t, cfg.lbConfig, cfg.kprConfig, tunnel.NewTestConfig(cfg.tunnelProtocol), fakewireguard.Config{})
		def.set()
	}
}

func TestLoadBalancerRSSCIDRIPv4Parsing(t *testing.T) {
	originalV4CIDR := option.Config.LoadBalancerRSSv4CIDR
	originalV4Prefix := option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv4
	originalDryMode := option.Config.DryMode
	t.Cleanup(func() {
		option.Config.LoadBalancerRSSv4CIDR = originalV4CIDR
		option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv4 = originalV4Prefix
		option.Config.DryMode = originalDryMode
	})
	option.Config.DryMode = true

	tests := []struct {
		name    string
		cidr    string
		want    netip.Prefix
		wantErr bool
	}{
		{
			name: "IPv4 prefix is masked",
			cidr: "192.0.2.129/24",
			want: netip.MustParsePrefix("192.0.2.0/24"),
		},
		{
			name:    "invalid IPv4 address is rejected",
			cidr:    "192.0.2.999/24",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.LoadBalancerRSSv4CIDR = ""
			option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv4 = netip.Prefix{}
			option.Config.LoadBalancerRSSv4CIDR = tt.cidr

			cfg := kprConfig{
				kubeProxyReplacement: true,
				routingMode:          option.RoutingModeNative,
				nodePortMode:         loadbalancer.LBModeDSR,
				dispatchMode:         loadbalancer.DSRDispatchIPIP,
			}
			require.NoError(t, cfg.set())

			initializer := &kprInitializer{
				logger:       hivetest.Logger(t),
				sysctl:       sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
				tunnelConfig: tunnel.NewTestConfig(cfg.tunnelProtocol),
				lbConfig:     cfg.lbConfig,
				kprCfg:       cfg.kprConfig,
				wgCfg:        fakewireguard.Config{},
			}
			err := initializer.InitKubeProxyReplacementOptions()
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv4)
		})
	}
}

func TestLoadBalancerRSSCIDRIPv6Parsing(t *testing.T) {
	originalV6CIDR := option.Config.LoadBalancerRSSv6CIDR
	originalV6Prefix := option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv6
	originalDryMode := option.Config.DryMode
	t.Cleanup(func() {
		option.Config.LoadBalancerRSSv6CIDR = originalV6CIDR
		option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv6 = originalV6Prefix
		option.Config.DryMode = originalDryMode
	})
	option.Config.DryMode = true

	tests := []struct {
		name    string
		cidr    string
		want    netip.Prefix
		wantErr bool
	}{
		{
			name: "IPv6 prefix is masked",
			cidr: "2001:db8::1/64",
			want: netip.MustParsePrefix("2001:db8::/64"),
		},
		{
			name:    "invalid IPv6 address is rejected",
			cidr:    "2001:db8::gg/64",
			wantErr: true,
		},
		{
			name:    "IPv4-mapped IPv6 prefix is rejected",
			cidr:    "::ffff:192.0.2.1/128",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.LoadBalancerRSSv6CIDR = ""
			option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv6 = netip.Prefix{}
			option.Config.LoadBalancerRSSv6CIDR = tt.cidr

			cfg := kprConfig{
				kubeProxyReplacement: true,
				routingMode:          option.RoutingModeNative,
				nodePortMode:         loadbalancer.LBModeDSR,
				dispatchMode:         loadbalancer.DSRDispatchIPIP,
			}
			require.NoError(t, cfg.set())

			initializer := &kprInitializer{
				logger:       hivetest.Logger(t),
				sysctl:       sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
				tunnelConfig: tunnel.NewTestConfig(cfg.tunnelProtocol),
				lbConfig:     cfg.lbConfig,
				kprCfg:       cfg.kprConfig,
				wgCfg:        fakewireguard.Config{},
			}
			err := initializer.InitKubeProxyReplacementOptions()
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv6)
		})
	}
}

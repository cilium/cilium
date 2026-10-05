// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

// TestNodeConfigIPMasqAgentIPv4 verifies that the enable_ip_masq_agent_ipv4
// node config variable is only set when BPF masquerading, IPv4 masquerading
// and the ip-masq-agent are all enabled, matching the semantics of the
// previous ENABLE_IP_MASQ_AGENT_IPV4 compile-time define.
func TestNodeConfigIPMasqAgentIPv4(t *testing.T) {
	oldBPFMasq := option.Config.EnableBPFMasquerade
	oldIPv4Masq := option.Config.EnableIPv4Masquerade
	oldIPMasqAgent := option.Config.EnableIPMasqAgent
	t.Cleanup(func() {
		option.Config.EnableBPFMasquerade = oldBPFMasq
		option.Config.EnableIPv4Masquerade = oldIPv4Masq
		option.Config.EnableIPMasqAgent = oldIPMasqAgent
	})

	tests := []struct {
		name        string
		bpfMasq     bool
		ipv4Masq    bool
		ipMasqAgent bool
		expected    bool
	}{
		{"all enabled", true, true, true, true},
		{"BPF masquerade disabled", false, true, true, false},
		{"IPv4 masquerade disabled", true, false, true, false},
		{"ip-masq-agent disabled", true, true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.EnableBPFMasquerade = tt.bpfMasq
			option.Config.EnableIPv4Masquerade = tt.ipv4Masq
			option.Config.EnableIPMasqAgent = tt.ipMasqAgent

			node := NodeConfig(&Config{})
			assert.Equal(t, tt.expected, node.EnableIPMasqAgentIPv4)
		})
	}
}

func TestNodeConfigNAT46X64Prefix(t *testing.T) {
	oldEnabled := option.Config.EnableNat46X64Gateway
	oldBase := option.Config.IPv6NAT46x64CIDRBase
	t.Cleanup(func() {
		option.Config.EnableNat46X64Gateway = oldEnabled
		option.Config.IPv6NAT46x64CIDRBase = oldBase
	})

	option.Config.IPv6NAT46x64CIDRBase = netip.MustParsePrefix(defaults.IPv6NAT46x64CIDR).Masked().Addr()

	option.Config.EnableNat46X64Gateway = false
	assert.Equal(t, [4]byte{}, NodeConfig(&Config{}).NAT46X64Prefix.Addr)

	option.Config.EnableNat46X64Gateway = true
	assert.Equal(t, [4]byte{0x00, 0x64, 0xff, 0x9b}, NodeConfig(&Config{}).NAT46X64Prefix.Addr)
}

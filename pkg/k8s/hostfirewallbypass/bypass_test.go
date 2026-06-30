// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hostfirewallbypass

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/option"
)

// TestNewK8sHostFirewallBypass locks down the decision matrix for whether the
// SO_MARK host-firewall bypass is installed on the k8s client dialer.
//
// The agent gates the bypass on host firewall via its DaemonConfig. The
// build-config init container, however, has no DaemonConfig (it is nil), so the
// only signal it has is the enable-k8s-host-firewall-bypass flag, which the Helm
// chart sets from hostFirewall.enabled. The bug in cilium/cilium#44464 was that
// the bypass was applied unconditionally in build-config (nil DaemonConfig +
// default-true flag), marking apiserver connections with the egress-proxy fwmark
// and breaking upgrades with kube-proxy in IPVS mode.
//
// The critical invariant the Helm fix relies on: when the flag is false the
// bypass MUST NOT be installed, regardless of DaemonConfig.
func TestNewK8sHostFirewallBypass(t *testing.T) {
	tests := []struct {
		name        string
		daemonCfg   *option.DaemonConfig
		flagEnabled bool
		wantBypass  bool
	}{
		{
			// build-config with the Helm fix on a cluster without host firewall:
			// this is the cilium/cilium#44464 scenario that must NOT bypass.
			name:        "no daemon config, flag disabled",
			daemonCfg:   nil,
			flagEnabled: false,
			wantBypass:  false,
		},
		{
			// build-config with the Helm fix on a host-firewall cluster: bypass is
			// needed to traverse the previous agent's host firewall during upgrade.
			name:        "no daemon config, flag enabled",
			daemonCfg:   nil,
			flagEnabled: true,
			wantBypass:  true,
		},
		{
			// agent: host firewall disabled wins even if the flag is on.
			name:        "daemon config host firewall disabled, flag enabled",
			daemonCfg:   &option.DaemonConfig{EnableHostFirewall: false},
			flagEnabled: true,
			wantBypass:  false,
		},
		{
			// agent: host firewall enabled and flag enabled -> bypass.
			name:        "daemon config host firewall enabled, flag enabled",
			daemonCfg:   &option.DaemonConfig{EnableHostFirewall: true},
			flagEnabled: true,
			wantBypass:  true,
		},
		{
			// agent: explicitly disabling the flag must win over host firewall.
			name:        "daemon config host firewall enabled, flag disabled",
			daemonCfg:   &option.DaemonConfig{EnableHostFirewall: true},
			flagEnabled: false,
			wantBypass:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewK8sHostFirewallBypass(Params{
				DaemonConfig: tt.daemonCfg,
				LocalConfig:  config{EnableK8sHostFirewallBypass: tt.flagEnabled},
			})
			require.Equal(t, tt.wantBypass, got != nil)
		})
	}
}

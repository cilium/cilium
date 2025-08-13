// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedCreateInPodRules(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := netlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// Create custom chains
		for _, table := range []string{"mangle", "nat"} {
			for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
				require.NoError(t, exec.WithTimeout(defaults.ExecTimeout, "iptables", "-t", table, "-N", chain).Run())
				require.NoError(t, exec.WithTimeout(defaults.ExecTimeout, "ip6tables", "-t", table, "-N", chain).Run())
			}
		}

		err = CreateInPodRules(slog.Default(), true, true)
		require.NoError(t, err)

		// Verify IPv4 rules
		mangleRulesV4 := getIPTablesRules(t, "iptables", "mangle")
		requireRule(t, mangleRulesV4, "-A", "PREROUTING", "-j", InpodPreroutingChain)
		requireRule(t, mangleRulesV4, "-A", "OUTPUT", "-j", InpodOutputChain)
		requireRule(t, mangleRulesV4, "-A", InpodPreroutingChain, "-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "CONNMARK", "--set-xmark", fmt.Sprintf("0x%x/0x%x", InpodTProxyMark, InpodMask))
		requireRule(t, mangleRulesV4, "-A", InpodOutputChain, "-m", "connmark", "--mark", fmt.Sprintf("0x%x/0x%x", InpodTProxyMark, InpodMask), "-j", "CONNMARK", "--restore-mark")

		natRulesV4 := getIPTablesRules(t, "iptables", "nat")
		requireRule(t, natRulesV4, "-A", "PREROUTING", "-j", InpodPreroutingChain)
		requireRule(t, natRulesV4, "-A", "OUTPUT", "-j", InpodOutputChain)
		requireRule(t, natRulesV4, "-A", InpodPreroutingChain, "!", "-d", "127.0.0.1/32", "-p", "tcp", "-m", "tcp", "!", "--dport", fmt.Sprint(ZtunnelInboundPort), "-m", "mark", "!", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "REDIRECT", "--to-ports", fmt.Sprint(ZtunnelInboundPlaintextPort))
		requireRule(t, natRulesV4, "-A", InpodOutputChain, "-p", "tcp", "-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", InpodTProxyMark, InpodMask), "-j", "ACCEPT")
		requireRule(t, natRulesV4, "-A", InpodOutputChain, "!", "-d", "127.0.0.1/32", "-o", "lo", "-j", "ACCEPT")
		requireRule(t, natRulesV4, "-A", InpodOutputChain, "!", "-d", "127.0.0.1/32", "-p", "tcp", "-m", "mark", "!", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", ZtunnelOutboundPort))

		// Verify IPv6 rules
		mangleRulesV6 := getIPTablesRules(t, "ip6tables", "mangle")
		requireRule(t, mangleRulesV6, "-A", "PREROUTING", "-j", InpodPreroutingChain)
		requireRule(t, mangleRulesV6, "-A", "OUTPUT", "-j", InpodOutputChain)
		requireRule(t, mangleRulesV6, "-A", InpodPreroutingChain, "-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "CONNMARK", "--set-xmark", fmt.Sprintf("0x%x/0x%x", InpodTProxyMark, InpodMask))
		requireRule(t, mangleRulesV6, "-A", InpodOutputChain, "-m", "connmark", "--mark", fmt.Sprintf("0x%x/0x%x", InpodTProxyMark, InpodMask), "-j", "CONNMARK", "--restore-mark")

		natRulesV6 := getIPTablesRules(t, "ip6tables", "nat")
		requireRule(t, natRulesV6, "-A", "PREROUTING", "-j", InpodPreroutingChain)
		requireRule(t, natRulesV6, "-A", "OUTPUT", "-j", InpodOutputChain)
		requireRule(t, natRulesV6, "-A", InpodPreroutingChain, "!", "-d", "::1/128", "-p", "tcp", "-m", "tcp", "!", "--dport", fmt.Sprint(ZtunnelInboundPort), "-m", "mark", "!", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "REDIRECT", "--to-ports", fmt.Sprint(ZtunnelInboundPlaintextPort))
		requireRule(t, natRulesV6, "-A", InpodOutputChain, "-p", "tcp", "-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", InpodTProxyMark, InpodMask), "-j", "ACCEPT")
		requireRule(t, natRulesV6, "-A", InpodOutputChain, "!", "-d", "::1/128", "-o", "lo", "-j", "ACCEPT")
		requireRule(t, natRulesV6, "-A", InpodOutputChain, "!", "-d", "::1/128", "-p", "tcp", "-m", "mark", "!", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", ZtunnelOutboundPort))

		return nil
	})
}

func getIPTablesRules(t *testing.T, cmd, table string) []string {
	out, err := exec.WithTimeout(defaults.ExecTimeout, cmd, "-t", table, "-S").Output(slog.Default(), false)
	require.NoError(t, err, "Failed to get iptables rules for table %s", table)
	return strings.Split(string(out), "\n")
}

func requireRule(t *testing.T, rules []string, expected ...string) {
	expectedRule := strings.Join(expected, " ")
	for _, rule := range rules {
		if strings.Contains(rule, expectedRule) {
			return
		}
	}
	require.Failf(t, "Rule not found", "rule containing '%s' not found in ruleset:\n%s", expectedRule, strings.Join(rules, "\n"))
}

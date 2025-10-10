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
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedCreateInPodRules(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
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

// TestPrivilegedCreateInPodRulesIdempotency tests that calling CreateInPodRules
// multiple times with existing rules, routes, and chains doesn't cause errors.
func TestPrivilegedCreateInPodRulesIdempotency(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// First call - creates all rules, routes, and chains
		err = CreateInPodRules(slog.Default(), true, true)
		require.NoError(t, err, "First call to CreateInPodRules should succeed")

		// Second call - should handle existing rules/routes/chains without error
		err = CreateInPodRules(slog.Default(), true, true)
		require.NoError(t, err, "Second call to CreateInPodRules should succeed (idempotency)")

		// Third call - verify it's truly idempotent
		err = CreateInPodRules(slog.Default(), true, true)
		require.NoError(t, err, "Third call to CreateInPodRules should succeed (idempotency)")

		return nil
	})
}

// TestPrivilegedAddExistingChains tests that creating chains that already exist
// doesn't cause errors.
func TestPrivilegedAddExistingChains(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		rm := ruleManager{logger: slog.Default()}

		// Create chains first time
		err = rm.createChains(true, true)
		require.NoError(t, err, "First call to createChains should succeed")

		// Create chains second time - should not error
		err = rm.createChains(true, true)
		require.NoError(t, err, "Second call to createChains should succeed")

		// Verify chains exist
		for _, table := range []string{"mangle", "nat"} {
			for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
				// IPv4
				_, err := exec.WithTimeout(defaults.ExecTimeout, "iptables", "-t", table, "-L", chain, "-n").Output(slog.Default(), false)
				require.NoError(t, err, "Chain %s should exist in IPv4 %s table", chain, table)

				// IPv6
				_, err = exec.WithTimeout(defaults.ExecTimeout, "ip6tables", "-t", table, "-L", chain, "-n").Output(slog.Default(), false)
				require.NoError(t, err, "Chain %s should exist in IPv6 %s table", chain, table)
			}
		}

		return nil
	})
}

// TestPrivilegedAddExistingRoutes tests that adding routes that already exist
// doesn't cause errors due to RouteReplace behavior.
func TestPrivilegedAddExistingRoutes(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// Add routes first time
		err = addLoopbackRoute(slog.Default(), true)
		require.NoError(t, err, "First call to addLoopbackRoute should succeed")

		// Add routes second time - should not error due to RouteReplace
		err = addLoopbackRoute(slog.Default(), true)
		require.NoError(t, err, "Second call to addLoopbackRoute should succeed")

		// Verify routes exist
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: RouteTableInbound,
		}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		require.NotEmpty(t, routes, "IPv4 routes should exist in table %d", RouteTableInbound)

		routesV6, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
			Table: RouteTableInbound,
		}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		require.NotEmpty(t, routesV6, "IPv6 routes should exist in table %d", RouteTableInbound)

		return nil
	})
}

// TestPrivilegedAddExistingMarkRules tests that adding netlink mark rules that
// already exist doesn't cause errors due to ReplaceRule behavior.
func TestPrivilegedAddExistingMarkRules(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// Add mark rules first time
		err = addInPodMarkRule(true)
		require.NoError(t, err, "First call to addInPodMarkRule should succeed")

		// Add mark rules second time - should not error due to ReplaceRule
		err = addInPodMarkRule(true)
		require.NoError(t, err, "Second call to addInPodMarkRule should succeed")

		// Verify IPv4 rule exists
		rules, err := netlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		foundV4 := false
		for _, rule := range rules {
			if rule.Priority == InpodRulePriority && rule.Mark == InpodTProxyMark && rule.Table == RouteTableInbound {
				foundV4 = true
				break
			}
		}
		require.True(t, foundV4, "IPv4 mark rule should exist")

		// Verify IPv6 rule exists
		rulesV6, err := netlink.RuleList(netlink.FAMILY_V6)
		require.NoError(t, err)
		foundV6 := false
		for _, rule := range rulesV6 {
			if rule.Priority == InpodRulePriority && rule.Mark == InpodTProxyMark && rule.Table == RouteTableInbound {
				foundV6 = true
				break
			}
		}
		require.True(t, foundV6, "IPv6 mark rule should exist")

		return nil
	})
}

// TestPrivilegedAddExistingIPTablesRules tests that adding iptables rules that
// already exist doesn't cause errors.
func TestPrivilegedAddExistingIPTablesRules(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// Create chains first
		rm := ruleManager{logger: slog.Default()}
		err = rm.createChains(true, true)
		require.NoError(t, err)

		// Install rules first time
		err = addInPodRules(slog.Default(), true, true)
		require.NoError(t, err, "First call to addInPodRules should succeed")

		// Install rules second time - should not error (rules already exist)
		err = addInPodRules(slog.Default(), true, true)
		require.NoError(t, err, "Second call to addInPodRules should succeed")

		// Verify that rules weren't duplicated
		natRulesV4 := getIPTablesRules(t, "iptables", "nat")

		// Count occurrences of a specific rule to ensure no duplication
		jumpCount := 0
		for _, rule := range natRulesV4 {
			if strings.Contains(rule, "-A PREROUTING -j "+InpodPreroutingChain) {
				jumpCount++
			}
		}
		require.Equal(t, 1, jumpCount, "Jump rule should appear exactly once, not duplicated")

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

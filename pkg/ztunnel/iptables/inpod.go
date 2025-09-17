// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
)

const (
	InpodPreroutingChain = "CILIUM_PREROUTING"
	InpodOutputChain     = "CILIUM_OUTPUT"

	RouteTableInbound = 100

	InpodRulePriority = 32764

	InpodTProxyMark  = 0x111
	InpodMark        = 0x539 // this needs to match the inpod config mark in ztunnel.
	InpodMask        = 0xfff
	InpodRestoreMask = 0xffffffff

	ZtunnelInboundPort          = 15008
	ZtunnelOutboundPort         = 15001
	ZtunnelInboundPlaintextPort = 15006

	VersionSpecificPlaceholder = "<VERSION_SPECIFIC>"
)

// CreateInPodRules creates the iptables rules for ztunnels inpod mode.
//
// Note that this function is supposed to be called from within the pods
// network namespace.
func CreateInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	if err := addLoopbackRoute(ipv6Enabled); err != nil {
		return err
	}

	if err := addInPodMarkRule(ipv6Enabled); err != nil {
		return err
	}

	if err := addInPodRules(logger, ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	return nil
}

func addLoopbackRoute(ipv6Enabled bool) error {
	loopbackLink, err := safenetlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to find 'lo' link: %w", err)
	}

	// Set up netlink routes for localhost
	cidrs := []string{"0.0.0.0/0"}
	if ipv6Enabled {
		cidrs = append(cidrs, "0::0/0")
	}
	for _, fullCIDR := range cidrs {
		_, localhostDst, err := net.ParseCIDR(fullCIDR)
		if err != nil {
			return fmt.Errorf("parse CIDR: %w", err)
		}

		// Equiv: "ip route add local 0.0.0.0/0 dev lo table 100"
		netlinkRoute := &netlink.Route{
			Dst:       localhostDst,
			Scope:     netlink.SCOPE_HOST,
			Type:      unix.RTN_LOCAL,
			Table:     RouteTableInbound,
			LinkIndex: loopbackLink.Attrs().Index,
		}

		// Use RouteReplace instead of RouteAdd to handle existing routes
		if err := netlink.RouteReplace(netlinkRoute); err != nil {
			return fmt.Errorf("failed to add route (%+v): %w", netlinkRoute, err)
		}
	}
	return nil
}

func addInPodMarkRule(ipv6Enabled bool) error {
	var rules []*netlink.Rule
	mask := uint32(InpodMask)

	inpodMarkRule := netlink.NewRule()
	inpodMarkRule.Family = unix.AF_INET
	inpodMarkRule.Table = RouteTableInbound
	inpodMarkRule.Mark = InpodTProxyMark
	inpodMarkRule.Mask = &mask
	inpodMarkRule.Priority = InpodRulePriority
	rules = append(rules, inpodMarkRule)

	if ipv6Enabled {
		inpodMarkRule6 := netlink.NewRule()
		inpodMarkRule6.Family = unix.AF_INET6
		inpodMarkRule6.Table = RouteTableInbound
		inpodMarkRule6.Mark = InpodTProxyMark
		inpodMarkRule6.Mask = &mask
		inpodMarkRule6.Priority = InpodRulePriority
		rules = append(rules, inpodMarkRule6)
	}

	for _, rule := range rules {
		// Check if rule already exists
		exists, err := lookupInpodRule(rule)
		if err != nil {
			return fmt.Errorf("failed to lookup netlink rule: %w", err)
		}
		if exists {
			continue // Rule already exists, skip adding
		}
		if err := netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("failed to configure netlink rule: %w", err)
		}
	}
	return nil
}

type rule struct {
	ipv4       string
	ipv6       string
	table      string
	chain      string
	parameters []string
}

type ruleManager struct {
	rules  []rule
	logger *slog.Logger
}

func (m *ruleManager) add(table, chain string, parameters ...string) {
	m.rules = append(m.rules, rule{"", "", table, chain, parameters})
}

func (m *ruleManager) addVersioned(ipv4, ipv6, table, chain string, parameters ...string) {
	m.rules = append(m.rules, rule{ipv4, ipv6, table, chain, parameters})
}

func replaceIPPlaceholder(args []string, ip string) []string {
	if ip == "" {
		return args
	}
	res := make([]string, len(args))
	copy(res, args)
	for i, arg := range args {
		if arg == VersionSpecificPlaceholder {
			res[i] = ip
		}
	}
	return res
}

func (m *ruleManager) install(ipv4Enabled, ipv6Enabled bool) error {
	for _, rule := range m.rules {
		args := []string{"-t", rule.table, "-C", rule.chain}
		args = append(args, rule.parameters...)
		if ipv4Enabled {
			// Check if rule exists
			_, checkErr := exec.WithTimeout(defaults.ExecTimeout, "iptables", replaceIPPlaceholder(args, rule.ipv4)...).Output(m.logger, false)
			if checkErr != nil {
				// Rule doesn't exist, add it
				args[2] = "-A" // -A for adding
				if _, err := exec.WithTimeout(defaults.ExecTimeout, "iptables", replaceIPPlaceholder(args, rule.ipv4)...).Output(m.logger, false); err != nil {
					return fmt.Errorf("failed to insert iptables rule (%v): %w", args, err)
				}
			}
		}

		if ipv6Enabled {
			// Check if rule exists
			_, checkErr := exec.WithTimeout(defaults.ExecTimeout, "ip6tables", replaceIPPlaceholder(args, rule.ipv6)...).Output(m.logger, false)

			if checkErr != nil {
				// Rule doesn't exist, add it
				args[2] = "-A" // -A for adding
				if _, err := exec.WithTimeout(defaults.ExecTimeout, "ip6tables", replaceIPPlaceholder(args, rule.ipv6)...).Output(m.logger, false); err != nil {
					return fmt.Errorf("failed to insert ip6tables rule (%v): %w", args, err)
				}
			}
		}
	}
	return nil
}

func (m *ruleManager) createChains(ipv4Enabled, ipv6Enabled bool) error {
	for _, table := range []string{"mangle", "nat"} {
		for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
			if ipv4Enabled {
				// Check if chain exists first
				_, checkErr := exec.WithTimeout(defaults.ExecTimeout, "iptables", "-t", table, "-L", chain, "-n").Output(m.logger, false)
				if checkErr != nil {
					// Chain doesn't exist, create it
					if _, err := exec.WithTimeout(defaults.ExecTimeout, "iptables", "-t", table, "-N", chain).Output(m.logger, false); err != nil {
						return fmt.Errorf("failed to create iptables chain %s: %w", chain, err)
					}
				}
			}
			if ipv6Enabled {
				// Check if chain exists first
				_, checkErr := exec.WithTimeout(defaults.ExecTimeout, "ip6tables", "-t", table, "-L", chain, "-n").Output(m.logger, false)
				if checkErr != nil {
					// Chain doesn't exist, create it
					if _, err := exec.WithTimeout(defaults.ExecTimeout, "ip6tables", "-t", table, "-N", chain).Output(m.logger, false); err != nil {
						return fmt.Errorf("failed to create ip6tables chain %s: %w", chain, err)
					}
				}
			}
		}
	}
	return nil
}

func addInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {

	rm := ruleManager{
		logger: logger,
	}

	if err := rm.createChains(ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	// Create jumps to custom chains. This isn't strictly necessary but it
	// makes it easier to identify those rules as being created by Cilium.
	// -t mangle -A PREROUTING -j CILIUM_PREROUTING
	rm.add("mangle", "PREROUTING", "-j", InpodPreroutingChain)
	// -t mangle -A OUTPUT -p tcp -j CILIUM_OUTPUT
	rm.add("mangle", "OUTPUT", "-j", InpodOutputChain)
	// -t nat -A PREROUTING -p tcp -j CILIUM_PREROUTING
	rm.add("nat", "PREROUTING", "-j", InpodPreroutingChain)
	// -t nat -A OUTPUT -p tcp -j CILIUM_OUTPUT
	rm.add("nat", "OUTPUT", "-j", InpodOutputChain)

	inpodMark := fmt.Sprintf("0x%x", InpodMark) + "/" + fmt.Sprintf("0x%x", InpodMask)
	inpodTproxyMark := fmt.Sprintf("0x%x", InpodTProxyMark) + "/" + fmt.Sprintf("0x%x", InpodMask)

	// If we have a packet mark, set a connmark.
	// -A CILIUM_PREROUTING -m mark --mark 0x539/0xfff -j CONNMARK --set-xmark 0x111/0xfff
	rm.add("mangle", InpodPreroutingChain, "-m", "mark",
		"--mark", inpodMark,
		"-j", "CONNMARK",
		"--set-xmark", inpodTproxyMark)

	// Anything that is not bound for localhost and does not have the mark, REDIRECT to ztunnel inbound plaintext port <INPLAINPORT>
	// Skip 15008, which will go direct without redirect needed.
	// -A CILIUM_PREROUTING ! -d 127.0.0.1/32 -p tcp ! --dport 15008 -m mark ! --mark 0x539/0xfff -j REDIRECT --to-ports <INPLAINPORT>
	rm.addVersioned(
		"127.0.0.1/32", "::1/128",
		"nat", InpodPreroutingChain,
		"!", "-d", VersionSpecificPlaceholder,
		"-p", "tcp",
		"-m", "tcp",
		"!", "--dport", fmt.Sprint(ZtunnelInboundPort),
		"-m", "mark",
		"!", "--mark", inpodMark,
		"-j", "REDIRECT",
		"--to-ports", fmt.Sprint(ZtunnelInboundPlaintextPort),
	)

	// Propagate/restore connmark (if we had one) for outbound
	// -A CILIUM_OUTPUT -m connmark --mark 0x111/0xfff -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
	rm.add("mangle", InpodOutputChain,
		"-m", "connmark",
		"--mark", inpodTproxyMark,
		"-j", "CONNMARK",
		"--restore-mark",
		"--nfmask", fmt.Sprintf("0x%x", InpodRestoreMask),
		"--ctmask", fmt.Sprintf("0x%x", InpodRestoreMask),
	)

	// If this is outbound and has our mark, let it go.
	// -A CILIUM_OUTPUT -p tcp -m mark --mark 0x111/0xfff -j ACCEPT
	rm.add("nat", InpodOutputChain,
		"-p", "tcp",
		"-m", "mark",
		"--mark", inpodTproxyMark,
		"-j", "ACCEPT")

	// Do not redirect app calls to back itself via Ztunnel when using the endpoint address
	// e.g. appN => appN by lo
	// -A CILIUM_OUTPUT ! -d 127.0.0.1/32 -o lo -j ACCEPT
	rm.addVersioned("127.0.0.1/32", "::1/128",
		"nat", InpodOutputChain,
		"!", "-d", VersionSpecificPlaceholder,
		"-o", "lo",
		"-j", "ACCEPT",
	)
	// If this is outbound, not bound for localhost, and does not have our packet mark, redirect to ztunnel proxy <OUTPORT>
	// -A CILIUM_OUTPUT ! -d 127.0.0.1/32 -p tcp -m mark ! --mark 0x539/0xfff -j REDIRECT --to-ports <OUTPORT>
	rm.addVersioned("127.0.0.1/32", "::1/128",
		"nat", InpodOutputChain,
		"!", "-d", VersionSpecificPlaceholder,
		"-p", "tcp",
		"-m", "mark",
		"!", "--mark", inpodMark,
		"-j", "REDIRECT",
		"--to-ports", fmt.Sprintf("%d", ZtunnelOutboundPort),
	)

	return rm.install(ipv4Enabled, ipv6Enabled)
}

// DeleteInPodRules removes the iptables rules for ztunnels inpod mode.
//
// Note that this function is supposed to be called from within the pods
// network namespace.
func DeleteInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	if err := deleteInPodChains(logger, ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	if err := deleteInPodMarkRule(ipv6Enabled); err != nil {
		return err
	}

	if err := deleteLoopbackRoute(ipv6Enabled); err != nil {
		return err
	}

	return nil
}

func deleteLoopbackRoute(ipv6Enabled bool) error {
	loopbackLink, err := safenetlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to find 'lo' link: %w", err)
	}

	cidrs := []string{"0.0.0.0/0"}
	if ipv6Enabled {
		cidrs = append(cidrs, "0::0/0")
	}
	for _, fullCIDR := range cidrs {
		_, localhostDst, err := net.ParseCIDR(fullCIDR)
		if err != nil {
			return fmt.Errorf("parse CIDR: %w", err)
		}

		netlinkRoute := &netlink.Route{
			Dst:       localhostDst,
			Scope:     netlink.SCOPE_HOST,
			Type:      unix.RTN_LOCAL,
			Table:     RouteTableInbound,
			LinkIndex: loopbackLink.Attrs().Index,
		}

		if err := netlink.RouteDel(netlinkRoute); err != nil {
			return fmt.Errorf("failed to delete route (%+v): %w", netlinkRoute, err)
		}
	}
	return nil
}

func deleteInPodMarkRule(ipv6Enabled bool) error {
	var rules []*netlink.Rule
	mask := uint32(InpodMask)

	inpodMarkRule := netlink.NewRule()
	inpodMarkRule.Family = unix.AF_INET
	inpodMarkRule.Table = RouteTableInbound
	inpodMarkRule.Mark = InpodTProxyMark
	inpodMarkRule.Mask = &mask
	inpodMarkRule.Priority = InpodRulePriority
	rules = append(rules, inpodMarkRule)

	if ipv6Enabled {
		inpodMarkRule6 := netlink.NewRule()
		inpodMarkRule6.Family = unix.AF_INET6
		inpodMarkRule6.Table = RouteTableInbound
		inpodMarkRule6.Mark = InpodTProxyMark
		inpodMarkRule6.Mask = &mask
		inpodMarkRule6.Priority = InpodRulePriority
		rules = append(rules, inpodMarkRule6)
	}

	for _, rule := range rules {
		if err := netlink.RuleDel(rule); err != nil {
			return fmt.Errorf("failed to delete netlink rule: %w", err)
		}
	}
	return nil
}

func deleteInPodChains(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	// First, delete the jump rules from the main chains to our custom chains
	for _, table := range []string{"mangle", "nat"} {
		jumpRules := map[string]string{
			"PREROUTING": InpodPreroutingChain,
			"OUTPUT":     InpodOutputChain,
		}

		for mainChain, customChain := range jumpRules {
			if ipv4Enabled {
				// Ignore errors - rule may not exist
				exec.WithTimeout(defaults.ExecTimeout, "iptables", "-t", table, "-D", mainChain, "-j", customChain).Output(logger, false)
			}
			if ipv6Enabled {
				// Ignore errors - rule may not exist
				exec.WithTimeout(defaults.ExecTimeout, "ip6tables", "-t", table, "-D", mainChain, "-j", customChain).Output(logger, false)
			}
		}
	}

	// Then flush and delete the custom chains
	for _, table := range []string{"mangle", "nat"} {
		for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
			if ipv4Enabled {
				exec.WithTimeout(defaults.ExecTimeout, "iptables", "-t", table, "-F", chain).Output(logger, false)
				if _, err := exec.WithTimeout(defaults.ExecTimeout, "iptables", "-t", table, "-X", chain).Output(logger, false); err != nil {
					return fmt.Errorf("failed to delete iptables chain %s: %w", chain, err)
				}
			}
			if ipv6Enabled {
				exec.WithTimeout(defaults.ExecTimeout, "ip6tables", "-t", table, "-F", chain).Output(logger, false)
				if _, err := exec.WithTimeout(defaults.ExecTimeout, "ip6tables", "-t", table, "-X", chain).Output(logger, false); err != nil {
					return fmt.Errorf("failed to delete ip6tables chain %s: %w", chain, err)
				}
			}
		}
	}
	return nil
}

// lookupInpodRule checks if a rule matching the spec already exists
func lookupInpodRule(spec *netlink.Rule) (bool, error) {
	rules, err := safenetlink.RuleList(spec.Family)
	if err != nil {
		return false, err
	}

	for _, r := range rules {
		if spec.Priority != 0 && spec.Priority != r.Priority {
			continue
		}
		if spec.Mark != 0 && r.Mark != spec.Mark {
			continue
		}
		if spec.Mask != nil && (r.Mask == nil || *r.Mask != *spec.Mask) {
			continue
		}
		if r.Table == spec.Table && r.Family == spec.Family {
			return true, nil
		}
	}
	return false, nil
}

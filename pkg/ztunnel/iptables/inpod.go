// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/route"
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
	if err := addLoopbackRoute(logger, ipv6Enabled); err != nil {
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

func addLoopbackRoute(logger *slog.Logger, ipv6Enabled bool) error {
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
		ciliumRoute := route.Route{
			Device: "lo",
			Prefix: *localhostDst,
			Scope:  netlink.SCOPE_HOST,
			Type:   unix.RTN_LOCAL,
			Table:  RouteTableInbound,
		}

		if err := route.Upsert(logger, ciliumRoute); err != nil {
			return fmt.Errorf("failed to add route (%+v): %w", ciliumRoute, err)
		}
	}
	return nil
}

func addInPodMarkRule(ipv6Enabled bool) error {
	mask := uint32(InpodMask)

	// IPv4 rule
	ipv4Rule := route.Rule{
		Priority: InpodRulePriority,
		Mark:     InpodTProxyMark,
		Mask:     mask,
		Table:    RouteTableInbound,
	}

	if err := route.ReplaceRule(ipv4Rule); err != nil {
		return fmt.Errorf("failed to configure IPv4 netlink rule: %w", err)
	}

	if ipv6Enabled {
		// IPv6 rule
		ipv6Rule := route.Rule{
			Priority: InpodRulePriority,
			Mark:     InpodTProxyMark,
			Mask:     mask,
			Table:    RouteTableInbound,
		}

		if err := route.ReplaceRuleIPv6(ipv6Rule); err != nil {
			return fmt.Errorf("failed to configure IPv6 netlink rule: %w", err)
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
	ipt4   *iptables.IPTables
	ipt6   *iptables.IPTables
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
		if ipv4Enabled {
			ruleSpec := replaceIPPlaceholder(rule.parameters, rule.ipv4)
			// Check if rule exists
			exists, err := m.ipt4.Exists(rule.table, rule.chain, ruleSpec...)
			if err != nil {
				return fmt.Errorf("failed to check iptables rule existence: %w", err)
			}
			if !exists {
				// Rule doesn't exist, add it
				if err := m.ipt4.Append(rule.table, rule.chain, ruleSpec...); err != nil {
					return fmt.Errorf("failed to insert iptables rule (%s %s %v): %w", rule.table, rule.chain, ruleSpec, err)
				}
			}
		}

		if ipv6Enabled && m.ipt6 != nil {
			ruleSpec := replaceIPPlaceholder(rule.parameters, rule.ipv6)
			// Check if rule exists
			exists, err := m.ipt6.Exists(rule.table, rule.chain, ruleSpec...)
			if err != nil {
				return fmt.Errorf("failed to check ip6tables rule existence: %w", err)
			}
			if !exists {
				// Rule doesn't exist, add it
				if err := m.ipt6.Append(rule.table, rule.chain, ruleSpec...); err != nil {
					return fmt.Errorf("failed to insert ip6tables rule (%s %s %v): %w", rule.table, rule.chain, ruleSpec, err)
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
				chainExists, err := m.ipt4.ChainExists(table, chain)
				if err != nil {
					return fmt.Errorf("failed to check iptables chain existence: %w", err)
				}

				if !chainExists {
					// Chain doesn't exist, create it
					if err := m.ipt4.NewChain(table, chain); err != nil {
						return fmt.Errorf("failed to create iptables chain %s: %w", chain, err)
					}
				}
			}

			if ipv6Enabled && m.ipt6 != nil {
				// Check if chain exists first
				chainExists, err := m.ipt6.ChainExists(table, chain)
				if err != nil {
					return fmt.Errorf("failed to check ip6tables chain existence: %w", err)
				}

				if !chainExists {
					// Chain doesn't exist, create it
					if err := m.ipt6.NewChain(table, chain); err != nil {
						return fmt.Errorf("failed to create ip6tables chain %s: %w", chain, err)
					}
				}
			}
		}
	}
	return nil
}

func addInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	var ipt4, ipt6 *iptables.IPTables
	var err error

	if ipv4Enabled {
		ipt4, err = iptables.New()
		if err != nil {
			return fmt.Errorf("failed to initialize iptables: %w", err)
		}
	}

	if ipv6Enabled {
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return fmt.Errorf("failed to initialize ip6tables: %w", err)
		}
	}

	rm := ruleManager{
		logger: logger,
		ipt4:   ipt4,
		ipt6:   ipt6,
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
	cidrs := []string{"0.0.0.0/0"}
	if ipv6Enabled {
		cidrs = append(cidrs, "0::0/0")
	}
	for _, fullCIDR := range cidrs {
		_, localhostDst, err := net.ParseCIDR(fullCIDR)
		if err != nil {
			return fmt.Errorf("parse CIDR: %w", err)
		}

		ciliumRoute := route.Route{
			Device: "lo",
			Prefix: *localhostDst,
			Scope:  netlink.SCOPE_HOST,
			Type:   unix.RTN_LOCAL,
			Table:  RouteTableInbound,
		}

		if err := route.Delete(ciliumRoute); err != nil {
			// Ignore ESRCH (no such process) and ENOENT (no such file or directory) errors,
			// which indicate the route was already deleted
			if !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("failed to delete route (%+v): %w", ciliumRoute, err)
			}
		}
	}
	return nil
}

func deleteInPodMarkRule(ipv6Enabled bool) error {
	mask := uint32(InpodMask)

	// IPv4 rule
	ipv4Rule := route.Rule{
		Priority: InpodRulePriority,
		Mark:     InpodTProxyMark,
		Mask:     mask,
		Table:    RouteTableInbound,
	}

	if err := route.DeleteRule(unix.AF_INET, ipv4Rule); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete IPv4 netlink rule: %w", err)
		}
	}

	if ipv6Enabled {
		// IPv6 rule
		ipv6Rule := route.Rule{
			Priority: InpodRulePriority,
			Mark:     InpodTProxyMark,
			Mask:     mask,
			Table:    RouteTableInbound,
		}

		if err := route.DeleteRule(unix.AF_INET6, ipv6Rule); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("failed to delete IPv6 netlink rule: %w", err)
			}
		}
	}
	return nil
}

func deleteInPodChains(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	var ipt4, ipt6 *iptables.IPTables
	var err error

	if ipv4Enabled {
		ipt4, err = iptables.New()
		if err != nil {
			return fmt.Errorf("failed to initialize iptables: %w", err)
		}
	}

	if ipv6Enabled {
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return fmt.Errorf("failed to initialize ip6tables: %w", err)
		}
	}

	// First, delete the jump rules from the main chains to our custom chains
	for _, table := range []string{"mangle", "nat"} {
		jumpRules := map[string]string{
			"PREROUTING": InpodPreroutingChain,
			"OUTPUT":     InpodOutputChain,
		}

		for mainChain, customChain := range jumpRules {
			if ipv4Enabled {
				// Ignore errors - rule may not exist
				_ = ipt4.Delete(table, mainChain, "-j", customChain)
			}
			if ipv6Enabled {
				// Ignore errors - rule may not exist
				_ = ipt6.Delete(table, mainChain, "-j", customChain)
			}
		}
	}

	// Then flush and delete the custom chains
	for _, table := range []string{"mangle", "nat"} {
		for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
			if ipv4Enabled {
				if err := ipt4.ClearChain(table, chain); err != nil {
					return fmt.Errorf("failed to flush iptables chain %s: %w", chain, err)
				}
				if err := ipt4.DeleteChain(table, chain); err != nil {
					return fmt.Errorf("failed to delete iptables chain %s: %w", chain, err)
				}
			}
			if ipv6Enabled {
				if err := ipt6.ClearChain(table, chain); err != nil {
					return fmt.Errorf("failed to flush ip6tables chain %s: %w", chain, err)
				}
				if err := ipt6.DeleteChain(table, chain); err != nil {
					return fmt.Errorf("failed to delete ip6tables chain %s: %w", chain, err)
				}
			}
		}
	}
	return nil
}

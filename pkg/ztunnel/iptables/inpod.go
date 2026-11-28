// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
)

const (
	InpodPreroutingChain = "CILIUM_PREROUTING"
	InpodOutputChain     = "CILIUM_OUTPUT"

	RouteTableInbound = 100

	InpodRulePriority = 32764

	// InpodTProxyMark and InpodMark are packet mark values used to coordinate traffic
	// redirection between Cilium and ztunnel. These values must remain synchronized
	// with ztunnel's inpod configuration.
	InpodTProxyMark  = 0x111 // Mark for traffic processed by ztunnel
	InpodMark        = 0x539 // Mark set by ztunnel on outbound traffic
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
func CreateInPodRules(logger *slog.Logger, runner iptables.Runner, ipv4Enabled, ipv6Enabled bool) error {
	if err := addLoopbackRoute(logger, ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	if err := addInPodMarkRule(ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	if err := addInPodRules(runner, ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	return nil
}

func addLoopbackRoute(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	// Set up netlink routes for localhost
	var cidrs []string
	if ipv4Enabled {
		cidrs = append(cidrs, "0.0.0.0/0")
	}
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

func addInPodMarkRule(ipv4Enabled, ipv6Enabled bool) error {
	mask := uint32(InpodMask)

	if ipv4Enabled {
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

// family runs the iptables commands of one IP family.
type family struct {
	ipv6 bool
	run  func(args ...string) (string, error)
}

// families returns the IP families to program with runner.
func families(runner iptables.Runner, ipv4Enabled, ipv6Enabled bool) []family {
	var fs []family
	if ipv4Enabled {
		fs = append(fs, family{ipv6: false, run: runner.RunIPv4})
	}
	if ipv6Enabled {
		fs = append(fs, family{ipv6: true, run: runner.RunIPv6})
	}
	return fs
}

func (f family) String() string {
	if f.ipv6 {
		return "ip6tables"
	}
	return "iptables"
}

// isNotFound reports whether err is iptables exiting with status 1, which is
// how "-C" and "-S <chain>" report that the rule or chain does not exist.
func isNotFound(err error) bool {
	exitErr, ok := errors.AsType[*exec.ExitError](err)
	return ok && exitErr.ExitCode() == 1
}

func (f family) ruleExists(table, chain string, ruleSpec []string) (bool, error) {
	_, err := f.run(append([]string{"-t", table, "-C", chain}, ruleSpec...)...)
	switch {
	case err == nil:
		return true, nil
	case isNotFound(err):
		return false, nil
	default:
		return false, err
	}
}

func (f family) chainExists(table, chain string) (bool, error) {
	_, err := f.run("-t", table, "-S", chain)
	switch {
	case err == nil:
		return true, nil
	case isNotFound(err):
		return false, nil
	default:
		return false, err
	}
}

type rule struct {
	ipv4       string
	ipv6       string
	table      string
	chain      string
	parameters []string
}

// spec returns the rule parameters for the given IP family.
func (r rule) spec(ipv6 bool) []string {
	if ipv6 {
		return replaceIPPlaceholder(r.parameters, r.ipv6)
	}
	return replaceIPPlaceholder(r.parameters, r.ipv4)
}

type ruleManager struct {
	rules    []rule
	families []family
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
	res := slices.Clone(args)
	for i, arg := range args {
		if arg == VersionSpecificPlaceholder {
			res[i] = ip
		}
	}
	return res
}

func (m *ruleManager) install() error {
	for _, rule := range m.rules {
		for _, f := range m.families {
			ruleSpec := rule.spec(f.ipv6)
			exists, err := f.ruleExists(rule.table, rule.chain, ruleSpec)
			if err != nil {
				return fmt.Errorf("failed to check %s rule existence: %w", f, err)
			}
			if exists {
				continue
			}
			if _, err := f.run(append([]string{"-t", rule.table, "-A", rule.chain}, ruleSpec...)...); err != nil {
				return fmt.Errorf("failed to insert %s rule (%s %s %v): %w", f, rule.table, rule.chain, ruleSpec, err)
			}
		}
	}
	return nil
}

func (m *ruleManager) createChains() error {
	for _, table := range []string{"mangle", "nat"} {
		for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
			for _, f := range m.families {
				exists, err := f.chainExists(table, chain)
				if err != nil {
					return fmt.Errorf("failed to check %s chain existence: %w", f, err)
				}
				if exists {
					continue
				}
				if _, err := f.run("-t", table, "-N", chain); err != nil {
					return fmt.Errorf("failed to create %s chain %s: %w", f, chain, err)
				}
			}
		}
	}
	return nil
}

// addInPodRules configures iptables rules for ztunnel's inpod mode traffic redirection.
//
// In inpod mode, ztunnel sets up listening sockets on specific ports within the application
// pod's network namespace to handle mTLS encryption/decryption for workload traffic. These
// iptables rules transparently redirect the application's TCP traffic to ztunnel's listening
// ports without requiring changes to the application itself.
//
// The rules implement the following traffic flow:
//
// Inbound Traffic (PREROUTING):
//   - Packets with the inpod mark (0x539) get their connmark set to the tproxy mark (0x111)
//   - Non-localhost TCP traffic without the inpod mark is redirected to ztunnel's inbound
//     plaintext port (15006), except for traffic already destined to port 15008
//
// Outbound Traffic (OUTPUT):
//   - Connmarks are restored to packet marks for connection tracking
//   - Traffic with the tproxy mark (0x111) is allowed through (already processed by ztunnel)
//   - Self-addressed traffic on loopback is allowed to bypass ztunnel
//   - All other non-localhost TCP traffic without the inpod mark is redirected to ztunnel's
//     outbound port (15001)
//
// The rules are created in custom chains (CILIUM_PREROUTING, CILIUM_OUTPUT) that are jumped
// to from the standard PREROUTING and OUTPUT chains in both the mangle and nat tables.
// This makes it easier to identify and manage Cilium-created rules.
func addInPodRules(runner iptables.Runner, ipv4Enabled, ipv6Enabled bool) error {
	rm := ruleManager{families: families(runner, ipv4Enabled, ipv6Enabled)}

	if err := rm.createChains(); err != nil {
		return err
	}

	// Jump to custom chains
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

	return rm.install()
}

// DeleteInPodRules removes the iptables rules for ztunnels inpod mode.
//
// Note that this function is supposed to be called from within the pods
// network namespace.
func DeleteInPodRules(runner iptables.Runner, ipv4Enabled, ipv6Enabled bool) error {
	if err := deleteInPodChains(runner, ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	if err := deleteInPodMarkRule(ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	if err := deleteLoopbackRoute(ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	return nil
}

func deleteLoopbackRoute(ipv4Enabled, ipv6Enabled bool) error {
	var cidrs []string
	if ipv4Enabled {
		cidrs = append(cidrs, "0.0.0.0/0")
	}
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

func deleteInPodMarkRule(ipv4Enabled, ipv6Enabled bool) error {
	mask := uint32(InpodMask)

	if ipv4Enabled {
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

func deleteInPodChains(runner iptables.Runner, ipv4Enabled, ipv6Enabled bool) error {
	fs := families(runner, ipv4Enabled, ipv6Enabled)

	// First, delete the jump rules from the main chains to our custom chains
	for _, table := range []string{"mangle", "nat"} {
		jumpRules := map[string]string{
			"PREROUTING": InpodPreroutingChain,
			"OUTPUT":     InpodOutputChain,
		}

		for mainChain, customChain := range jumpRules {
			for _, f := range fs {
				// Ignore errors - rule may not exist
				_, _ = f.run("-t", table, "-D", mainChain, "-j", customChain)
			}
		}
	}

	// Then flush and delete the custom chains
	for _, table := range []string{"mangle", "nat"} {
		for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
			for _, f := range fs {
				exists, err := f.chainExists(table, chain)
				if err != nil {
					return fmt.Errorf("failed to check %s chain existence: %w", f, err)
				}
				if !exists {
					continue
				}
				if _, err := f.run("-t", table, "-F", chain); err != nil {
					return fmt.Errorf("failed to flush %s chain %s: %w", f, chain, err)
				}
				if _, err := f.run("-t", table, "-X", chain); err != nil {
					return fmt.Errorf("failed to delete %s chain %s: %w", f, chain, err)
				}
			}
		}
	}
	return nil
}

// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iptables

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/modules"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/versioncheck"

	go_version "github.com/hashicorp/go-version"
	"github.com/mattn/go-shellwords"
)

const (
	ciliumPrefix                = "CILIUM_"
	ciliumInputChain            = "CILIUM_INPUT"
	ciliumOutputChain           = "CILIUM_OUTPUT"
	ciliumOutputRawChain        = "CILIUM_OUTPUT_raw"
	ciliumPostNatChain          = "CILIUM_POST_nat"
	ciliumOutputNatChain        = "CILIUM_OUTPUT_nat"
	ciliumPreNatChain           = "CILIUM_PRE_nat"
	ciliumPostMangleChain       = "CILIUM_POST_mangle"
	ciliumPreMangleChain        = "CILIUM_PRE_mangle"
	ciliumPreRawChain           = "CILIUM_PRE_raw"
	ciliumForwardChain          = "CILIUM_FORWARD"
	ciliumTransientForwardChain = "CILIUM_TRANSIENT_FORWARD"
	feederDescription           = "cilium-feeder:"
	xfrmDescription             = "cilium-xfrm-notrack:"
)

// Minimum iptables versions supporting the -w and -w<seconds> flags
var (
	waitMinVersion        = versioncheck.MustCompile(">=v1.4.20")
	waitSecondsMinVersion = versioncheck.MustCompile(">=v1.4.22")
)

const (
	waitString       = "-w"
	waitSecondsValue = "5"
)

type customChain struct {
	name       string
	table      string
	hook       string
	feederArgs []string
	ipv6       bool // ip6tables chain in addition to iptables chain
}

func getVersion(prog string) (*go_version.Version, error) {
	b, err := exec.WithTimeout(defaults.ExecTimeout, prog, "--version").CombinedOutput(log, false)
	if err != nil {
		return nil, err
	}
	v := regexp.MustCompile("v([0-9]+(\\.[0-9]+)+)")
	vString := v.FindStringSubmatch(string(b))
	if vString == nil {
		return nil, fmt.Errorf("no iptables version found in string: %s", string(b))
	}
	return go_version.NewVersion(vString[1])
}

func runProg(prog string, args []string, quiet bool) error {
	_, err := exec.WithTimeout(defaults.ExecTimeout, prog, args...).CombinedOutput(log, !quiet)
	return err
}

func getFeedRule(name, args string) []string {
	ruleTail := []string{"-m", "comment", "--comment", feederDescription + " " + name, "-j", name}
	if args == "" {
		return ruleTail
	}
	argsList, err := shellwords.Parse(args)
	if err != nil {
		log.WithError(err).WithField(logfields.Object, args).Fatal("Unable to parse rule into argument slice")
	}
	return append(argsList, ruleTail...)
}

func (c *customChain) add(waitArgs []string) error {
	var err error
	if option.Config.EnableIPv4 {
		err = runProg("iptables", append(waitArgs, "-t", c.table, "-N", c.name), false)
	}
	if err == nil && option.Config.EnableIPv6 && c.ipv6 == true {
		err = runProg("ip6tables", append(waitArgs, "-t", c.table, "-N", c.name), false)
	}
	return err
}

func reverseRule(rule string) ([]string, error) {
	if strings.HasPrefix(rule, "-A") {
		// From: -A POSTROUTING -m comment [...]
		// To:   -D POSTROUTING -m comment [...]
		return shellwords.Parse(strings.Replace(rule, "-A", "-D", 1))
	}

	if strings.HasPrefix(rule, "-I") {
		// From: -I POSTROUTING -m comment [...]
		// To:   -D POSTROUTING -m comment [...]
		return shellwords.Parse(strings.Replace(rule, "-I", "-D", 1))
	}

	return []string{}, nil
}

func (m *IptablesManager) removeCiliumRules(table, prog, match string) {
	args := append(m.waitArgs, "-t", table, "-S")

	out, err := exec.WithTimeout(defaults.ExecTimeout, prog, args...).CombinedOutput(log, true)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		rule := scanner.Text()
		log.WithField(logfields.Object, logfields.Repr(rule)).Debugf("Considering removing %s rule", prog)
		if match != ciliumTransientForwardChain && strings.Contains(rule, ciliumTransientForwardChain) {
			continue
		}

		// All rules installed by cilium either belong to a chain with
		// the name CILIUM_ or call a chain with the name CILIUM_:
		// -A CILIUM_FORWARD -o cilium_host -m comment --comment "cilium: any->cluster on cilium_host forward accept" -j ACCEPT
		// -A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST" -j CILIUM_POST
		if strings.Contains(rule, match) {
			reversedRule, err := reverseRule(rule)
			if err != nil {
				log.WithError(err).WithField(logfields.Object, rule).Warnf("Unable to parse %s rule into slice. Leaving rule behind.", prog)
				continue
			}

			if len(reversedRule) > 0 {
				deleteRule := append(append(m.waitArgs, "-t", table), reversedRule...)
				log.WithField(logfields.Object, logfields.Repr(deleteRule)).Debugf("Removing %s rule", prog)
				err = runProg(prog, deleteRule, true)
				if err != nil {
					log.WithError(err).WithField(logfields.Object, rule).Warnf("Unable to delete Cilium %s rule", prog)
				}
			}
		}
	}
}

func (c *customChain) remove(waitArgs []string, quiet bool) {
	if option.Config.EnableIPv4 {
		prog := "iptables"
		args := append(waitArgs, "-t", c.table, "-F", c.name)
		err := runProg(prog, args, true)
		if err != nil && !quiet {
			log.WithError(err).WithField(logfields.Object, args).Warnf("Unable to flush Cilium %s chain", prog)
		}

		args = append(waitArgs, "-t", c.table, "-X", c.name)
		err = runProg(prog, args, true)
		if err != nil && !quiet {
			log.WithError(err).WithField(logfields.Object, args).Warnf("Unable to delete Cilium %s chain", prog)
		}
	}
	if option.Config.EnableIPv6 && c.ipv6 == true {
		prog := "ip6tables"
		args := append(waitArgs, "-t", c.table, "-F", c.name)
		err := runProg(prog, args, true)
		if err != nil && !quiet {
			log.WithError(err).WithField(logfields.Object, args).Warnf("Unable to flush Cilium %s chain", prog)
		}

		args = append(waitArgs, "-t", c.table, "-X", c.name)
		err = runProg(prog, args, true)
		if err != nil && !quiet {
			log.WithError(err).WithField(logfields.Object, args).Warnf("Unable to delete Cilium %s chain", prog)
		}
	}
}

func (c *customChain) installFeeder(waitArgs []string) error {
	installMode := "-A"
	if option.Config.PrependIptablesChains {
		installMode = "-I"
	}

	for _, feedArgs := range c.feederArgs {
		if option.Config.EnableIPv4 {
			err := runProg("iptables", append(append(waitArgs, "-t", c.table, installMode, c.hook), getFeedRule(c.name, feedArgs)...), true)
			if err != nil {
				return err
			}
		}
		if option.Config.EnableIPv6 && c.ipv6 == true {
			err := runProg("ip6tables", append(append(waitArgs, "-t", c.table, installMode, c.hook), getFeedRule(c.name, feedArgs)...), true)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// ciliumChains is the list of custom iptables chain used by Cilium. Custom
// chains are used to allow for simple replacements of all rules.
//
// WARNING: If you change or remove any of the feeder rules you have to ensure
// that the old feeder rules is also removed on agent start, otherwise,
// flushing and removing the custom chains will fail.
var ciliumChains = []customChain{
	{
		name:       ciliumInputChain,
		table:      "filter",
		hook:       "INPUT",
		feederArgs: []string{""},
		ipv6:       true,
	},
	{
		name:       ciliumOutputChain,
		table:      "filter",
		hook:       "OUTPUT",
		feederArgs: []string{""},
		ipv6:       true,
	},
	{
		name:       ciliumOutputRawChain,
		table:      "raw",
		hook:       "OUTPUT",
		feederArgs: []string{""},
		ipv6:       true,
	},
	{
		name:       ciliumPostNatChain,
		table:      "nat",
		hook:       "POSTROUTING",
		feederArgs: []string{""},
	},
	{
		name:       ciliumOutputNatChain,
		table:      "nat",
		hook:       "OUTPUT",
		feederArgs: []string{""},
	},
	{
		name:       ciliumPreNatChain,
		table:      "nat",
		hook:       "PREROUTING",
		feederArgs: []string{""},
	},
	{
		name:       ciliumPostMangleChain,
		table:      "mangle",
		hook:       "POSTROUTING",
		feederArgs: []string{""},
	},
	{
		name:       ciliumPreMangleChain,
		table:      "mangle",
		hook:       "PREROUTING",
		feederArgs: []string{""},
		ipv6:       true,
	},
	{
		name:       ciliumPreRawChain,
		table:      "raw",
		hook:       "PREROUTING",
		feederArgs: []string{""},
		ipv6:       true,
	},
	{
		name:       ciliumForwardChain,
		table:      "filter",
		hook:       "FORWARD",
		feederArgs: []string{""},
	},
}

var transientChain = customChain{
	name:       ciliumTransientForwardChain,
	table:      "filter",
	hook:       "FORWARD",
	feederArgs: []string{""},
}

// IptablesManager manages the iptables-related configuration for Cilium.
type IptablesManager struct {
	haveIp6tables   bool
	haveSocketMatch bool
	waitArgs        []string
}

// Init initializes the iptables manager and checks for iptables kernel modules
// availability.
func (m *IptablesManager) Init() {
	modulesManager := &modules.ModulesManager{}
	ip6tables := true
	if err := modulesManager.Init(); err != nil {
		log.WithError(err).Fatal(
			"Unable to get information about kernel modules")
	}
	if err := modulesManager.FindOrLoadModules(
		"ip_tables", "iptable_nat", "iptable_mangle", "iptable_raw",
		"iptable_filter"); err != nil {
		log.WithError(err).Warning(
			"iptables modules could not be initialized. It probably means that iptables is not available on this system")
	}
	if err := modulesManager.FindOrLoadModules(
		"ip6_tables", "ip6table_mangle", "ip6table_raw", "ip6table_filter"); err != nil {
		if option.Config.EnableIPv6 {
			log.WithError(err).Warning(
				"IPv6 is enabled and ip6tables modules could not be initialized")
		}
		log.WithError(err).Debug(
			"ip6tables kernel modules could not be loaded, so IPv6 cannot be used")
		ip6tables = false
	}
	m.haveIp6tables = ip6tables

	if err := modulesManager.FindOrLoadModules("xt_socket"); err != nil {
		log.WithError(err).Warning("xt_socket kernel module could not be loaded")
		if option.Config.Tunnel == option.TunnelDisabled {
			log.Warning("Traffic to endpoints with L7 ingress policy may be dropped unexpectedly")
		}
	} else {
		m.haveSocketMatch = true
	}

	v, err := getVersion("iptables")
	if err == nil {
		switch {
		case waitSecondsMinVersion.Check(v):
			m.waitArgs = []string{waitString, waitSecondsValue}
		case waitMinVersion.Check(v):
			m.waitArgs = []string{waitString}
		}
	}
}

func (m *IptablesManager) SupportsOriginalSourceAddr() bool {
	return m.haveSocketMatch
}

// RemoveRules removes iptables rules installed by Cilium.
func (m *IptablesManager) RemoveRules() {
	// Set of tables that have had iptables rules in any Cilium version
	tables := []string{"nat", "mangle", "raw", "filter"}
	for _, t := range tables {
		m.removeCiliumRules(t, "iptables", ciliumPrefix)
	}

	// Set of tables that have had ip6tables rules in any Cilium version
	if m.haveIp6tables {
		tables6 := []string{"mangle", "raw", "filter"}
		for _, t := range tables6 {
			m.removeCiliumRules(t, "ip6tables", ciliumPrefix)
		}
	}

	for _, c := range ciliumChains {
		c.remove(m.waitArgs, false)
	}
}

func (m *IptablesManager) ingressProxyRule(cmd, l4Match, markMatch, mark, port, name string) []string {
	return append(m.waitArgs,
		"-t", "mangle",
		cmd, ciliumPreMangleChain,
		"-p", l4Match,
		"-m", "mark", "--mark", markMatch,
		"-m", "comment", "--comment", "cilium: TPROXY to host "+name+" proxy",
		"-j", "TPROXY",
		"--tproxy-mark", mark,
		"--on-port", port)
}

func (m *IptablesManager) inboundProxyRedirectRule(cmd string) []string {
	// Mark host proxy transparent connections to be routed to the local stack.
	// This comes before the TPROXY rules in the chain, and setting the mark
	// without the proxy port number will make the TPROXY rule to not match,
	// as we do not want to try to tproxy packets that are going to the stack
	// already.
	// This rule is needed for couple of reasons:
	// 1. route return traffic to the proxy
	// 2. route original direction traffic that would otherwise be intercepted
	//    by ip_early_demux
	toProxyMark := fmt.Sprintf("%#08x", linux_defaults.MagicMarkIsToProxy)
	return append(m.waitArgs,
		"-t", "mangle",
		cmd, ciliumPreMangleChain,
		"-m", "socket", "--transparent", "--nowildcard",
		"-m", "comment", "--comment", "cilium: any->pod redirect proxied traffic to host proxy",
		"-j", "MARK",
		"--set-mark", toProxyMark)
}

func (m *IptablesManager) iptIngressProxyRule(cmd string, l4proto string, proxyPort uint16, name string) error {
	// Match
	port := uint32(byteorder.HostToNetwork(proxyPort).(uint16)) << 16
	ingressMarkMatch := fmt.Sprintf("%#08x", linux_defaults.MagicMarkIsToProxy|port)
	// TPROXY params
	ingressProxyMark := fmt.Sprintf("%#08x", linux_defaults.MagicMarkIsToProxy)
	ingressProxyPort := fmt.Sprintf("%d", proxyPort)

	var err error
	if option.Config.EnableIPv4 {
		err = runProg("iptables",
			m.ingressProxyRule(cmd, l4proto, ingressMarkMatch,
				ingressProxyMark, ingressProxyPort, name),
			false)
	}
	if err == nil && option.Config.EnableIPv6 {
		err = runProg("ip6tables",
			m.ingressProxyRule(cmd, l4proto, ingressMarkMatch,
				ingressProxyMark, ingressProxyPort, name),
			false)
	}
	return err
}

func (m *IptablesManager) egressProxyRule(cmd, l4Match, markMatch, mark, port, name string) []string {
	return append(m.waitArgs,
		"-t", "mangle",
		cmd, ciliumPreMangleChain,
		"-p", l4Match,
		"-m", "mark", "--mark", markMatch,
		"-m", "comment", "--comment", "cilium: TPROXY to host "+name+" proxy",
		"-j", "TPROXY",
		"--tproxy-mark", mark,
		"--on-port", port)
}

func (m *IptablesManager) iptEgressProxyRule(cmd string, l4proto string, proxyPort uint16, name string) error {
	// Match
	port := uint32(byteorder.HostToNetwork(proxyPort).(uint16)) << 16
	egressMarkMatch := fmt.Sprintf("%#08x", linux_defaults.MagicMarkIsToProxy|port)
	// TPROXY params
	egressProxyMark := fmt.Sprintf("%#08x", linux_defaults.MagicMarkIsToProxy)
	egressProxyPort := fmt.Sprintf("%d", proxyPort)

	var err error
	if option.Config.EnableIPv4 {
		err = runProg("iptables",
			m.egressProxyRule(cmd, l4proto, egressMarkMatch,
				egressProxyMark, egressProxyPort, name),
			false)
	}
	if err == nil && option.Config.EnableIPv6 {
		err = runProg("ip6tables",
			m.egressProxyRule(cmd, l4proto, egressMarkMatch,
				egressProxyMark, egressProxyPort, name),
			false)
	}
	return err
}

func (m *IptablesManager) installStaticProxyRules() error {
	// match traffic to a proxy (upper 16 bits has the proxy port, which is masked out)
	matchToProxy := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsToProxy, linux_defaults.MagicMarkHostMask)
	// proxy return traffic has 0 ID in the mask
	matchProxyReply := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxy, linux_defaults.MagicMarkProxyNoIDMask)

	var err error
	if option.Config.EnableIPv4 {
		// No conntrack for traffic to proxy
		err = runProg("iptables", append(
			m.waitArgs,
			"-t", "raw",
			"-A", ciliumPreRawChain,
			// Destination is a local node POD address
			"!", "-d", node.GetInternalIPv4().String(),
			"-m", "mark", "--mark", matchToProxy,
			"-m", "comment", "--comment", "cilium: NOTRACK for proxy traffic",
			"-j", "NOTRACK"), false)
		if err == nil {
			// Explicit ACCEPT for the proxy traffic. Needed when the INPUT defaults to DROP.
			// Matching needs to be the same as for the NOTRACK rule above.
			err = runProg("iptables", append(
				m.waitArgs,
				"-t", "filter",
				"-A", ciliumInputChain,
				// Destination is a local node POD address
				"!", "-d", node.GetInternalIPv4().String(),
				"-m", "mark", "--mark", matchToProxy,
				"-m", "comment", "--comment", "cilium: ACCEPT for proxy traffic",
				"-j", "ACCEPT"), false)
		}
		if err == nil {
			// No conntrack for proxy return traffic
			err = runProg("iptables", append(
				m.waitArgs,
				"-t", "raw",
				"-A", ciliumOutputRawChain,
				// Return traffic is from a local node POD address
				"!", "-s", node.GetInternalIPv4().String(),
				"-m", "mark", "--mark", matchProxyReply,
				"-m", "comment", "--comment", "cilium: NOTRACK for proxy return traffic",
				"-j", "NOTRACK"), false)
		}
		if err == nil {
			// Explicit ACCEPT for the proxy return traffic. Needed when the OUTPUT defaults to DROP.
			// Matching needs to be the same as for the NOTRACK rule above.
			err = runProg("iptables", append(
				m.waitArgs,
				"-t", "filter",
				"-A", ciliumOutputChain,
				// Return traffic is from a local node POD address
				"!", "-s", node.GetInternalIPv4().String(),
				"-m", "mark", "--mark", matchProxyReply,
				"-m", "comment", "--comment", "cilium: ACCEPT for proxy return traffic",
				"-j", "ACCEPT"), false)
		}
		if err == nil && m.haveSocketMatch {
			// Direct inbound TPROXYed traffic towards the socket
			err = runProg("iptables", m.inboundProxyRedirectRule("-A"), false)
		}
	}
	if err == nil && option.Config.EnableIPv6 {
		// No conntrack for traffic to ingress proxy
		err = runProg("ip6tables", append(
			m.waitArgs,
			"-t", "raw",
			"-A", ciliumPreRawChain,
			// Destination is a local node POD address
			"!", "-d", node.GetIPv6().String(),
			"-m", "mark", "--mark", matchToProxy,
			"-m", "comment", "--comment", "cilium: NOTRACK for proxy traffic",
			"-j", "NOTRACK"), false)
		if err == nil {
			// Explicit ACCEPT for the proxy traffic. Needed when the INPUT defaults to DROP.
			// Matching needs to be the same as for the NOTRACK rule above.
			err = runProg("ip6tables", append(
				m.waitArgs,
				"-t", "filter",
				"-A", ciliumInputChain,
				// Destination is a local node POD address
				"!", "-d", node.GetIPv6().String(),
				"-m", "mark", "--mark", matchToProxy,
				"-m", "comment", "--comment", "cilium: ACCEPT for proxy traffic",
				"-j", "ACCEPT"), false)
		}
		if err == nil {
			// No conntrack for proxy return traffic
			err = runProg("ip6tables", append(
				m.waitArgs,
				"-t", "raw",
				"-A", ciliumOutputRawChain,
				// Return traffic is from a local node POD address
				"!", "-s", node.GetIPv6().String(),
				"-m", "mark", "--mark", matchProxyReply,
				"-m", "comment", "--comment", "cilium: NOTRACK for proxy return traffic",
				"-j", "NOTRACK"), false)
		}
		if err == nil {
			// Explicit ACCEPT for the proxy return traffic. Needed when the OUTPUT defaults to DROP.
			// Matching needs to be the same as for the NOTRACK rule above.
			err = runProg("ip6tables", append(
				m.waitArgs,
				"-t", "filter",
				"-A", ciliumOutputChain,
				// Return traffic is from a local node POD address
				"!", "-s", node.GetIPv6().String(),
				"-m", "mark", "--mark", matchProxyReply,
				"-m", "comment", "--comment", "cilium: ACCEPT for proxy return traffic",
				"-j", "ACCEPT"), false)
		}
		if err == nil && m.haveSocketMatch {
			// Direct inbound TPROXYed traffic towards the socket
			err = runProg("ip6tables", m.inboundProxyRedirectRule("-A"), false)
		}
	}
	return err
}

// install or remove rules for a single proxy port
func (m *IptablesManager) iptProxyRules(cmd string, proxyPort uint16, ingress bool, name string) error {
	// Redirect packets to the host proxy via TPROXY, as directed by the Cilium
	// datapath bpf programs via skb marks (egress) or DSCP (ingress).
	if ingress {
		if err := m.iptIngressProxyRule(cmd, "tcp", proxyPort, name); err != nil {
			return err
		}
		if err := m.iptIngressProxyRule(cmd, "udp", proxyPort, name); err != nil {
			return err
		}
	} else {
		if err := m.iptEgressProxyRule(cmd, "tcp", proxyPort, name); err != nil {
			return err
		}
		if err := m.iptEgressProxyRule(cmd, "udp", proxyPort, name); err != nil {
			return err
		}
	}
	return nil
}

func (m *IptablesManager) InstallProxyRules(proxyPort uint16, ingress bool, name string) error {
	return m.iptProxyRules("-A", proxyPort, ingress, name)
}

func (m *IptablesManager) RemoveProxyRules(proxyPort uint16, ingress bool, name string) error {
	return m.iptProxyRules("-D", proxyPort, ingress, name)
}

func (m *IptablesManager) remoteSnatDstAddrExclusion() string {
	switch {
	case option.Config.IPv4NativeRoutingCIDR() != nil:
		return option.Config.IPv4NativeRoutingCIDR().String()

	case option.Config.Tunnel == option.TunnelDisabled:
		return node.GetIPv4ClusterRange().String()

	default:
		return node.GetIPv4AllocRange().String()
	}
}

func getDeliveryInterface(ifName string) string {
	deliveryInterface := ifName
	if option.Config.IPAM == option.IPAMENI || option.Config.EnableEndpointRoutes {
		deliveryInterface = "lxc+"
	}
	return deliveryInterface
}

// TransientRulesStart installs iptables rules for Cilium that need to be
// kept in-tact during agent restart which removes/installs its main rules.
// Transient rules are then removed once iptables rule update cycle has
// completed. This is mainly due to interactions with kube-proxy.
func (m *IptablesManager) TransientRulesStart(ifName string) error {
	if option.Config.EnableIPv4 {
		localDeliveryInterface := getDeliveryInterface(ifName)

		m.TransientRulesEnd(true)

		if err := transientChain.add(m.waitArgs); err != nil {
			return fmt.Errorf("cannot add custom chain %s: %s", transientChain.name, err)
		}
		// While kube-proxy does change the policy of the iptables FORWARD chain
		// it doesn't seem to handle all cases, e.g. host network pods that use
		// the node IP which would still end up in default DENY. Similarly, for
		// plain Docker setup, we would otherwise hit default DENY in FORWARD chain.
		// Also, k8s 1.15 introduced "-m conntrack --ctstate INVALID -j DROP" which
		// in the direct routing case can drop EP replies.
		// Therefore, add both rules below to avoid having a user to manually opt-in.
		// See also: https://github.com/kubernetes/kubernetes/issues/39823
		// In here can only be basic ACCEPT rules, nothing more complicated.
		if err := runProg("iptables", append(
			m.waitArgs,
			"-A", ciliumTransientForwardChain,
			"-o", localDeliveryInterface,
			"-m", "comment", "--comment", "cilium (transient): any->cluster on "+localDeliveryInterface+" forward accept",
			"-j", "ACCEPT"), false); err != nil {
			return err
		}
		if err := runProg("iptables", append(
			m.waitArgs,
			"-A", ciliumTransientForwardChain,
			"-i", "lxc+",
			"-m", "comment", "--comment", "cilium (transient): cluster->any on lxc+ forward accept",
			"-j", "ACCEPT"), false); err != nil {
			return err
		}
		if err := transientChain.installFeeder(m.waitArgs); err != nil {
			return fmt.Errorf("cannot install feeder rule %s: %s", transientChain.feederArgs, err)
		}
	}
	return nil
}

// TransientRulesEnd removes Cilium related rules installed from TransientRulesStart.
func (m *IptablesManager) TransientRulesEnd(quiet bool) {
	if option.Config.EnableIPv4 {
		m.removeCiliumRules("filter", "iptables", ciliumTransientForwardChain)
		transientChain.remove(m.waitArgs, quiet)
	}
}

// InstallRules installs iptables rules for Cilium in specific use-cases
// (most specifically, interaction with kube-proxy).
func (m *IptablesManager) InstallRules(ifName string) error {
	matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
	matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)
	localDeliveryInterface := getDeliveryInterface(ifName)

	for _, c := range ciliumChains {
		if err := c.add(m.waitArgs); err != nil {
			return fmt.Errorf("cannot add custom chain %s: %s", c.name, err)
		}
	}

	if err := m.installStaticProxyRules(); err != nil {
		return fmt.Errorf("cannot add static proxy rules: %s", err)
	}

	if err := m.addCiliumAcceptXfrmRules(); err != nil {
		return err
	}

	if option.Config.EnableIPv4 {
		// Clear the Kubernetes masquerading mark bit to skip source PAT
		// performed by kube-proxy for all packets destined for Cilium. Cilium
		// installs a dedicated rule which does the source PAT to the right
		// source IP.
		clearMasqBit := fmt.Sprintf("%#08x/%#08x", 0, linux_defaults.MagicMarkK8sMasq)
		if err := runProg("iptables", append(
			m.waitArgs,
			"-t", "mangle",
			"-A", ciliumPostMangleChain,
			"-o", localDeliveryInterface,
			"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
			"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
			"-m", "comment", "--comment", "cilium: clear masq bit for pkts to "+localDeliveryInterface,
			"-j", "MARK", "--set-xmark", clearMasqBit), false); err != nil {
			return err
		}

		// See kube-proxy comment in TransientRules().
		if err := runProg("iptables", append(
			m.waitArgs,
			"-A", ciliumForwardChain,
			"-o", localDeliveryInterface,
			"-m", "comment", "--comment", "cilium: any->cluster on "+localDeliveryInterface+" forward accept",
			"-j", "ACCEPT"), false); err != nil {
			return err
		}
		if err := runProg("iptables", append(
			m.waitArgs,
			"-A", ciliumForwardChain,
			"-i", "lxc+",
			"-m", "comment", "--comment", "cilium: cluster->any on lxc+ forward accept",
			"-j", "ACCEPT"), false); err != nil {
			return err
		}

		// Mark all packets sourced from processes running on the host with a
		// special marker so that we can differentiate traffic sourced locally
		// vs. traffic from the outside world that was masqueraded to appear
		// like it's from the host.
		//
		// Originally we set this mark only for traffic destined to the
		// ifName device, to ensure that any traffic directly reaching
		// to a Cilium-managed IP could be classified as from the host.
		//
		// However, there's another case where a local process attempts to
		// reach a service IP which is backed by a Cilium-managed pod. The
		// service implementation is outside of Cilium's control, for example,
		// handled by kube-proxy. We can tag even this traffic with a magic
		// mark, then when the service implementation proxies it back into
		// Cilium the BPF will see this mark and understand that the packet
		// originated from the host.
		matchFromProxy := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxy, linux_defaults.MagicMarkProxyMask)
		markAsFromHost := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkHost, linux_defaults.MagicMarkHostMask)
		if err := runProg("iptables", append(
			m.waitArgs,
			"-t", "filter",
			"-A", ciliumOutputChain,
			"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
			"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
			"-m", "mark", "!", "--mark", matchFromProxy, // Don't match proxy traffic
			"-m", "comment", "--comment", "cilium: host->any mark as from host",
			"-j", "MARK", "--set-xmark", markAsFromHost), false); err != nil {
			return err
		}

		if option.Config.Masquerade {
			// Masquerade all egress traffic leaving the node
			//
			// This rule must be first as it has different exclusion criteria
			// than the other rules in this table.
			//
			// The following conditions must be met:
			// * May not leave on a cilium_ interface, this excludes all
			//   tunnel traffic
			// * Must originate from an IP in the local allocation range
			// * Must not be reply if BPF NodePort is enabled
			// * Tunnel mode:
			//   * May not be targeted to an IP in the local allocation
			//     range
			// * Non-tunnel mode:
			//   * May not be targeted to an IP in the cluster range
			if option.Config.EgressMasqueradeInterfaces != "" {
				if err := runProg("iptables", append(
					m.waitArgs,
					"-t", "nat",
					"-A", ciliumPostNatChain,
					"!", "-d", m.remoteSnatDstAddrExclusion(),
					"-o", option.Config.EgressMasqueradeInterfaces,
					"-m", "comment", "--comment", "cilium masquerade non-cluster",
					"-j", "MASQUERADE"), false); err != nil {
					return err
				}
			} else {
				if err := runProg("iptables", append(
					m.waitArgs,
					"-t", "nat",
					"-A", ciliumPostNatChain,
					"-s", node.GetIPv4AllocRange().String(),
					"!", "-d", m.remoteSnatDstAddrExclusion(),
					"!", "-o", "cilium_+",
					"-m", "comment", "--comment", "cilium masquerade non-cluster",
					"-j", "MASQUERADE"), false); err != nil {
					return err
				}
			}

			// The following rules exclude traffic from the remaining rules in this chain.
			// If any of these rules match, none of the remaining rules in this chain
			// are considered.
			// Exclude traffic for other than interface from the masquarade rules.
			// RETURN fro the chain as it is possible that other rules need to be matched.
			if err := runProg("iptables", append(
				m.waitArgs,
				"-t", "nat",
				"-A", ciliumPostNatChain,
				"!", "-o", localDeliveryInterface,
				"-m", "comment", "--comment", "exclude non-"+ifName+" traffic from masquerade",
				"-j", "RETURN"), false); err != nil {
				return err
			}

			// Exclude proxy return traffic from the masquarade rules
			if err := runProg("iptables", append(
				m.waitArgs,
				"-t", "nat",
				"-A", ciliumPostNatChain,
				"-m", "mark", "--mark", matchFromProxy, // Don't match proxy (return) traffic
				"-m", "comment", "--comment", "exclude proxy return traffic from masquarade",
				"-j", "ACCEPT"), false); err != nil {
				return err
			}

			if option.Config.Tunnel != option.TunnelDisabled {
				// Masquerade all traffic from the host into the ifName
				// interface if the source is not the internal IP
				//
				// The following conditions must be met:
				// * Must be targeted for the ifName interface
				// * Must be targeted to an IP that is not local
				// * Tunnel mode:
				//   * May not already be originating from the masquerade IP
				// * Non-tunnel mode:
				//   * May not orignate from any IP inside of the cluster range
				if err := runProg("iptables", append(
					m.waitArgs,
					"-t", "nat",
					"-A", ciliumPostNatChain,
					"!", "-s", node.GetHostMasqueradeIPv4().String(),
					"!", "-d", node.GetIPv4AllocRange().String(),
					"-o", "cilium_host",
					"-m", "comment", "--comment", "cilium host->cluster masquerade",
					"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()), false); err != nil {
					return err
				}
			}

			// Masquerade all traffic from the host into local
			// endpoints if the source is 127.0.0.1. This is
			// required to force replies out of the endpoint's
			// network namespace.
			//
			// The following conditions must be met:
			// * Must be targeted for local endpoint
			// * Must be from 127.0.0.1
			if err := runProg("iptables", append(
				m.waitArgs,
				"-t", "nat",
				"-A", ciliumPostNatChain,
				"-s", "127.0.0.1",
				"-o", localDeliveryInterface,
				"-m", "comment", "--comment", "cilium host->cluster from 127.0.0.1 masquerade",
				"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()), false); err != nil {
				return err
			}

			if !option.Config.EnableNodePort {
				// Masquerade all traffic from a local endpoint that is routed
				// back to an endpoint on the same node. This happens if a
				// local endpoint talks to a Kubernetes NodePort or HostPort.
				if err := runProg("iptables", append(
					m.waitArgs,
					"-t", "nat",
					"-A", ciliumPostNatChain,
					"-s", node.GetIPv4AllocRange().String(),
					"-m", "comment", "--comment", "cilium hostport loopback masquerade",
					"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()), false); err != nil {
					return err
				}
			}

			// Masquerade all traffic from the host into the
			// local Cilium cluster range if the source is not
			// in the cluster range and DNAT has been
			// applied.  These conditions are met by traffic
			// redirected via hostports from non-cluster sources.
			// The SNAT to the cluster address is needed so that
			// the return traffic from a host proxy (when used) is
			// routed back via the cilium_host device also
			// when the source address is originally
			// outside of the cluster range.
			//
			// The following conditions must be met:
			// * Must be targeted to an IP that IS local
			// * May not originate from any IP inside of the cluster range
			// * Must have DNAT applied (k8s hostport, etc.)

			if err := runProg("iptables", append(
				m.waitArgs,
				"-t", "nat",
				"-A", ciliumPostNatChain,
				"!", "-s", node.GetIPv4ClusterRange().String(),
				"-o", localDeliveryInterface,
				"-m", "conntrack", "--ctstate", "DNAT",
				"-m", "comment", "--comment", "cilium hostport cluster masquerade",
				"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()), false); err != nil {
				return err
			}
		}
	}

	if option.Config.EnableIPSec {
		if err := m.addCiliumNoTrackXfrmRules(); err != nil {
			return fmt.Errorf("cannot install xfrm rules: %s", err)
		}
	}

	for _, c := range ciliumChains {
		if err := c.installFeeder(m.waitArgs); err != nil {
			return fmt.Errorf("cannot install feeder rule %s: %s", c.feederArgs, err)
		}
	}

	return nil
}

func (m *IptablesManager) ciliumNoTrackXfrmRules(prog, input string) error {
	matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
	matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)

	if err := runProg(prog, append(
		m.waitArgs,
		"-t", "raw", input, ciliumPreRawChain,
		"-m", "mark", "--mark", matchFromIPSecDecrypt,
		"-m", "comment", "--comment", xfrmDescription,
		"-j", "NOTRACK"), false); err != nil {
		return err
	}
	if err := runProg(prog, append(
		m.waitArgs,
		"-t", "raw", input, ciliumPreRawChain,
		"-m", "mark", "--mark", matchFromIPSecEncrypt,
		"-m", "comment", "--comment", xfrmDescription,
		"-j", "NOTRACK"), false); err != nil {
		return err
	}
	return nil
}

// Exclude crypto traffic from the filter and nat table rules.
// This avoids encryption bits and keyID, 0x*d00 for decryption
// and 0x*e00 for encryption, colliding with existing rules. Needed
// for kube-proxy for example.
func (m *IptablesManager) addCiliumAcceptXfrmRules() error {
	if option.Config.EnableIPSec == false {
		return nil
	}
	insertAcceptXfrm := func(table, chain string) error {
		matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
		matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)

		comment := "exclude xfrm marks from " + table + " " + chain + " chain"

		if err := runProg("iptables", append(
			m.waitArgs,
			"-t", table,
			"-A", chain,
			"-m", "mark", "--mark", matchFromIPSecEncrypt,
			"-m", "comment", "--comment", comment,
			"-j", "ACCEPT"), false); err != nil {
			return err
		}

		return runProg("iptables", append(
			m.waitArgs,
			"-t", table,
			"-A", chain,
			"-m", "mark", "--mark", matchFromIPSecDecrypt,
			"-m", "comment", "--comment", comment,
			"-j", "ACCEPT"), false)
	}
	if err := insertAcceptXfrm("filter", ciliumInputChain); err != nil {
		return err
	}
	if err := insertAcceptXfrm("filter", ciliumOutputChain); err != nil {
		return err
	}
	if err := insertAcceptXfrm("filter", ciliumForwardChain); err != nil {
		return err
	}
	if err := insertAcceptXfrm("nat", ciliumPostNatChain); err != nil {
		return err
	}
	if err := insertAcceptXfrm("nat", ciliumPreNatChain); err != nil {
		return err
	}
	if err := insertAcceptXfrm("nat", ciliumOutputNatChain); err != nil {
		return err
	}
	return nil
}

func (m *IptablesManager) addCiliumNoTrackXfrmRules() error {
	if option.Config.EnableIPv4 {
		return m.ciliumNoTrackXfrmRules("iptables", "-I")
	}
	return nil
}

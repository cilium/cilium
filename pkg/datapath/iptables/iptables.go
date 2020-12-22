// Copyright 2016-2020 Authors of Cilium
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
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/modules"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/blang/semver/v4"
	"github.com/mattn/go-shellwords"
	"github.com/sirupsen/logrus"
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
	isWaitMinVersion        = versioncheck.MustCompile(">=1.4.20")
	isWaitSecondsMinVersion = versioncheck.MustCompile(">=1.4.22")
	noTrackPorts            = func(port uint16) []*lb.L4Addr {
		return []*lb.L4Addr{
			{
				Protocol: lb.TCP,
				Port:     port,
			},
			{
				Protocol: lb.UDP,
				Port:     port,
			},
		}
	}
)

const (
	waitString = "-w"
)

type customChain struct {
	name       string
	table      string
	hook       string
	feederArgs []string
	ipv6       bool // ip6tables chain in addition to iptables chain
}

func getVersion(prog string) (semver.Version, error) {
	b, err := exec.WithTimeout(defaults.ExecTimeout, prog, "--version").CombinedOutput(log, false)
	if err != nil {
		return semver.Version{}, err
	}
	v := regexp.MustCompile("v([0-9]+(\\.[0-9]+)+)")
	vString := v.FindStringSubmatch(string(b))
	if vString == nil {
		return semver.Version{}, fmt.Errorf("no iptables version found in string: %s", string(b))
	}
	return versioncheck.Version(vString[1])
}

func runProgCombinedOutput(prog string, args []string, quiet bool) ([]byte, error) {
	out, err := exec.WithTimeout(defaults.ExecTimeout, prog, args...).CombinedOutput(log, !quiet)
	return out, err
}

func runProg(prog string, args []string, quiet bool) error {
	_, err := runProgCombinedOutput(prog, args, quiet)
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

// KernelHasNetfilter probes whether iptables related modules are present in
// the kernel and returns true if indeed the case, else false.
func KernelHasNetfilter() bool {
	modulesManager := &modules.ModulesManager{}
	if err := modulesManager.Init(); err != nil {
		return true
	}
	if found, _ := modulesManager.FindModules(
		"ip_tables", "iptable_mangle", "iptable_raw", "iptable_filter"); found {
		return true
	}
	if found, _ := modulesManager.FindModules(
		"ip6_tables", "ip6table_mangle", "ip6table_raw", "ip6table_filter"); found {
		return true
	}
	return false
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
			// do not remove feeder for chains that are set to be disabled
			// ie catch the beginning of the rule like -A POSTROUTING to match it against
			// disabled chains
			skipFeeder := false
			for _, disabledChain := range option.Config.DisableIptablesFeederRules {
				// we skip if the match is ciliumTransientForwardChain since we don't want to touch it
				if match != ciliumTransientForwardChain && strings.Contains(rule, " "+strings.ToUpper(disabledChain)+" ") {
					log.WithField("chain", disabledChain).Info("Skipping the removal of feeder chain")
					skipFeeder = true
					break
				}
			}
			if skipFeeder {
				continue
			}

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
	doProcess := func(c *customChain, prog string, args []string, operation string, quiet bool) {
		combinedOutput, err := runProgCombinedOutput(prog, args, true)
		if err != nil {
			// If the chain is for transient rules and deletion
			// fails for a reason other than the chain not being
			// present, log the error.
			// This is to help debug #11276.
			msgChainNotFound := ": No chain/target/match by that name.\n"
			debugTransientRules := c.name == ciliumTransientForwardChain &&
				string(combinedOutput) != prog+msgChainNotFound
			if !quiet || debugTransientRules {
				log.Warnf(string(combinedOutput))
				log.WithError(err).WithField(logfields.Object, args).Warnf("Unable to process chain %s with %s (%s)", c.name, prog, operation)
			}
		}
	}
	doRemove := func(c *customChain, prog string, waitArgs []string, quiet bool) {
		args := append(waitArgs, "-t", c.table, "-F", c.name)
		doProcess(c, prog, args, "flush", quiet)
		args = append(waitArgs, "-t", c.table, "-X", c.name)
		doProcess(c, prog, args, "delete", quiet)
	}
	if option.Config.EnableIPv4 {
		prog := "iptables"
		doRemove(c, prog, waitArgs, quiet)
	}
	if option.Config.EnableIPv6 && c.ipv6 {
		prog := "ip6tables"
		doRemove(c, prog, waitArgs, quiet)
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
		ipv6:       true,
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
	haveIp6tables        bool
	haveSocketMatch      bool
	haveBPFSocketAssign  bool
	ipEarlyDemuxDisabled bool
	waitArgs             []string
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
		if option.Config.Tunnel == option.TunnelDisabled {
			// xt_socket module is needed to circumvent an explicit drop in ip_forward()
			// logic for packets for which a local socket is found by ip early
			// demux. xt_socket performs a local socket match and sets an skb mark on
			// match, which will divert the packet to the local stack using our policy
			// routing rule, thus avoiding being processed by ip_forward() at all.
			//
			// If xt_socket module does not exist we can disable ip early demux to to
			// avoid the explicit drop in ip_forward(). This is not needed in tunneling
			// modes, as then we'll set the skb mark in the bpf logic before the policy
			// routing stage so that the packet is routed locally instead of being
			// forwarded by ip_forward().
			//
			// We would not need the xt_socket at all if the datapath universally would
			// set the "to proxy" skb mark bits on before the packet hits policy routing
			// stage. Currently this is not true for endpoint routing modes.
			log.WithError(err).Warning("xt_socket kernel module could not be loaded")

			if option.Config.EnableXTSocketFallback {
				v4disabled := true
				v6disabled := true
				if option.Config.EnableIPv4 {
					v4disabled = sysctl.Disable("net.ipv4.ip_early_demux") == nil
				}
				if option.Config.EnableIPv6 {
					v6disabled = sysctl.Disable("net.ipv6.ip_early_demux") == nil
				}
				if v4disabled && v6disabled {
					m.ipEarlyDemuxDisabled = true
					log.Warning("Disabled ip_early_demux to allow proxy redirection with original source/destination address without xt_socket support also in non-tunneled datapath modes.")
				} else {
					log.WithError(err).Warning("Could not disable ip_early_demux, traffic redirected due to an HTTP policy or visibility may be dropped unexpectedly")
				}
			}
		}
	} else {
		m.haveSocketMatch = true
	}
	m.haveBPFSocketAssign = option.Config.EnableBPFTProxy

	v, err := getVersion("iptables")
	if err == nil {
		switch {
		case isWaitSecondsMinVersion(v):
			m.waitArgs = []string{waitString, fmt.Sprintf("%d", option.Config.IPTablesLockTimeout/time.Second)}
		case isWaitMinVersion(v):
			m.waitArgs = []string{waitString}
		}
	}
}

// SupportsOriginalSourceAddr tells if an L7 proxy can use POD's original source address and port in
// the upstream connection to allow the destination to properly derive the source security ID from
// the source IP address.
func (m *IptablesManager) SupportsOriginalSourceAddr() bool {
	// Original source address use works if xt_socket match is supported, or if ip early demux
	// is disabled, or if the datapath is in a tunneling mode.
	return m.haveSocketMatch || m.ipEarlyDemuxDisabled || option.Config.Tunnel != option.TunnelDisabled
}

// RemoveRules removes iptables rules installed by Cilium.
func (m *IptablesManager) RemoveRules(quiet bool) {
	// Set of tables that have had iptables rules in any Cilium version
	tables := []string{"nat", "mangle", "raw", "filter"}
	for _, t := range tables {
		m.removeCiliumRules(t, "iptables", ciliumPrefix)
	}

	// Set of tables that have had ip6tables rules in any Cilium version
	if m.haveIp6tables {
		tables6 := []string{"nat", "mangle", "raw", "filter"}
		for _, t := range tables6 {
			m.removeCiliumRules(t, "ip6tables", ciliumPrefix)
		}
	}

	for _, c := range ciliumChains {
		c.remove(m.waitArgs, quiet)
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
		"-m", "socket", "--transparent",
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
				"-m", "mark", "--mark", matchToProxy,
				"-m", "comment", "--comment", "cilium: ACCEPT for proxy traffic",
				"-j", "ACCEPT"), false)
		}
		if err == nil {
			// No conntrack for proxy return traffic that is heading to lxc+
			err = runProg("iptables", append(
				m.waitArgs,
				"-t", "raw",
				"-A", ciliumOutputRawChain,
				"-o", "lxc+",
				"-m", "mark", "--mark", matchProxyReply,
				"-m", "comment", "--comment", "cilium: NOTRACK for proxy return traffic",
				"-j", "NOTRACK"), false)
		}
		if err == nil {
			// No conntrack for proxy return traffic that is heading to cilium_host
			err = runProg("iptables", append(
				m.waitArgs,
				"-t", "raw",
				"-A", ciliumOutputRawChain,
				"-o", "cilium_host",
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

func noTrackRules(prog string, cmd string, IP string, port *lb.L4Addr, ingress bool) error {
	protocol := strings.ToLower(port.Protocol)
	p := strconv.FormatUint(uint64(port.Port), 10)
	if ingress {
		if _, err := runProgCombinedOutput(prog, []string{"-t", "raw", cmd, "PREROUTING", "-p", protocol, "-d", IP, "--dport", p, "-j", "NOTRACK"}, false); err != nil {
			return err
		}
		if _, err := runProgCombinedOutput(prog, []string{"-t", "filter", cmd, "INPUT", "-p", protocol, "-d", IP, "--dport", p, "-j", "ACCEPT"}, false); err != nil {
			return err
		}
		if _, err := runProgCombinedOutput(prog, []string{"-t", "raw", cmd, "OUTPUT", "-p", protocol, "-d", IP, "--dport", p, "-j", "NOTRACK"}, false); err != nil {
			return err
		}
	} else {
		if _, err := runProgCombinedOutput(prog, []string{"-t", "raw", cmd, "OUTPUT", "-p", protocol, "-s", IP, "--sport", p, "-j", "NOTRACK"}, false); err != nil {
			return err
		}
		if _, err := runProgCombinedOutput(prog, []string{"-t", "filter", cmd, "OUTPUT", "-p", protocol, "-s", IP, "--sport", p, "-j", "ACCEPT"}, false); err != nil {
			return err
		}
	}
	return nil
}

func InstallNoTrackRules(IP string, port uint16, ipv6 bool) error {
	prog := "iptables"
	ipField := logfields.IPv4
	if ipv6 {
		prog = "ip6tables"
		ipField = logfields.IPv6
	}
	ports := noTrackPorts(port)
	for _, p := range ports {
		if err := noTrackRules(prog, "-A", IP, p, true); err != nil {
			log.WithFields(logrus.Fields{
				ipField:            IP,
				logfields.Port:     p.Port,
				logfields.Protocol: p.Protocol,
			}).WithError(err).Warn("Unable to install ingress NOTRACK rules")
			return err
		}
		if err := noTrackRules(prog, "-A", IP, p, false); err != nil {
			log.WithFields(logrus.Fields{
				ipField:            IP,
				logfields.Port:     p.Port,
				logfields.Protocol: p.Protocol,
			}).WithError(err).Warn("Unable to install egress NOTRACK rules")
			return err
		}
	}
	return nil
}

func RemoveNoTrackRules(IP string, port uint16, ipv6 bool) error {
	prog := "iptables"
	ipField := logfields.IPv4
	if ipv6 {
		prog = "ip6tables"
		ipField = logfields.IPv6
	}
	ports := noTrackPorts(port)
	for _, p := range ports {
		if err := noTrackRules(prog, "-D", IP, p, true); err != nil {
			log.WithFields(logrus.Fields{
				ipField:            IP,
				logfields.Port:     p.Port,
				logfields.Protocol: p.Protocol,
			}).WithError(err).Warn("Unable to remove ingress NOTRACK rules")
			return err
		}
		if err := noTrackRules(prog, "-D", IP, p, false); err != nil {
			log.WithFields(logrus.Fields{
				ipField:            IP,
				logfields.Port:     p.Port,
				logfields.Protocol: p.Protocol,
			}).WithError(err).Warn("Unable to remove egress NOTRACK rules")
			return err
		}
	}
	return nil
}

func (m *IptablesManager) InstallProxyRules(proxyPort uint16, ingress bool, name string) error {
	if m.haveBPFSocketAssign {
		log.WithField("port", proxyPort).
			Debug("Skipping proxy rule install due to BPF support")
		return nil
	}
	return m.iptProxyRules("-A", proxyPort, ingress, name)
}

// GetProxyPort finds a proxy port used for redirect 'name' installed earlier with InstallProxyRules.
// By convention "ingress" or "egress" is part of 'name' so it does not need to be specified explicitly.
// Returns 0 a TPROXY entry with 'name' can not be found.
func (m *IptablesManager) GetProxyPort(name string) uint16 {
	prog := "iptables"
	if !option.Config.EnableIPv4 {
		prog = "ip6tables"
	}

	res, err := runProgCombinedOutput(prog, []string{"-t", "mangle", "-n", "-L", ciliumPreMangleChain}, false)
	if err != nil {
		return 0
	}

	re := regexp.MustCompile(name + ".*TPROXY redirect 0.0.0.0:([1-9][0-9]*) mark")
	str := re.FindString(string(res))
	portStr := re.ReplaceAllString(str, "$1")
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		log.WithError(err).Debugf("Port number cannot be parsed: %s", portStr)
		return 0
	}
	return uint16(portInt)
}

func (m *IptablesManager) RemoveProxyRules(proxyPort uint16, ingress bool, name string) error {
	return m.iptProxyRules("-D", proxyPort, ingress, name)
}

func getDeliveryInterface(ifName string) string {
	deliveryInterface := ifName
	if option.Config.IPAM == ipamOption.IPAMENI || option.Config.EnableEndpointRoutes {
		deliveryInterface = "lxc+"
	}
	return deliveryInterface
}

func (m *IptablesManager) installForwardChainRules(ifName, localDeliveryInterface, forwardChain string) error {
	transient := ""
	if forwardChain == ciliumTransientForwardChain {
		transient = " (transient)"
	}

	// While kube-proxy does change the policy of the iptables FORWARD chain
	// it doesn't seem to handle all cases, e.g. host network pods that use
	// the node IP which would still end up in default DENY. Similarly, for
	// plain Docker setup, we would otherwise hit default DENY in FORWARD chain.
	// Also, k8s 1.15 introduced "-m conntrack --ctstate INVALID -j DROP" which
	// in the direct routing case can drop EP replies.
	//
	// Therefore, add the rules below to avoid having a user to manually opt-in.
	// See also: https://github.com/kubernetes/kubernetes/issues/39823
	// In here can only be basic ACCEPT rules, nothing more complicated.
	//
	// The 2nd and 3rd rule are for the case of nodeport traffic where the backend is
	// remote. The traffic flow in FORWARD is as follows:
	//
	//  - Node serving nodeport request:
	//      IN=eno1 OUT=cilium_host
	//      IN=cilium_host OUT=eno1
	//
	//  - Node running backend:
	//       IN=eno1 OUT=cilium_host
	//       IN=lxc... OUT=eno1
	if err := runProg("iptables", append(
		m.waitArgs,
		"-A", forwardChain,
		"-o", ifName,
		"-m", "comment", "--comment", "cilium"+transient+": any->cluster on "+ifName+" forward accept",
		"-j", "ACCEPT"), false); err != nil {
		return err
	}
	if err := runProg("iptables", append(
		m.waitArgs,
		"-A", forwardChain,
		"-i", ifName,
		"-m", "comment", "--comment", "cilium"+transient+": cluster->any on "+ifName+" forward accept (nodeport)",
		"-j", "ACCEPT"), false); err != nil {
		return err
	}
	if err := runProg("iptables", append(
		m.waitArgs,
		"-A", forwardChain,
		"-i", "lxc+",
		"-m", "comment", "--comment", "cilium"+transient+": cluster->any on lxc+ forward accept",
		"-j", "ACCEPT"), false); err != nil {
		return err
	}
	// Proxy return traffic to a remote source needs '-i cilium_net'.
	// TODO: Make 'cilium_net' configurable if we ever support other than "cilium_host" as the Cilium host device.
	if ifName == "cilium_host" {
		ifPeerName := "cilium_net"
		if err := runProg("iptables", append(
			m.waitArgs,
			"-A", forwardChain,
			"-i", ifPeerName,
			"-m", "comment", "--comment", "cilium"+transient+": cluster->any on "+ifPeerName+" forward accept (nodeport)",
			"-j", "ACCEPT"), false); err != nil {
			return err
		}
	}
	// In case the delivery interface and the host interface are not the
	// same (enable-endpoint-routes), a separate set of rules to allow
	// from/to delivery interface is required.
	if localDeliveryInterface != ifName {
		if err := runProg("iptables", append(
			m.waitArgs,
			"-A", forwardChain,
			"-o", localDeliveryInterface,
			"-m", "comment", "--comment", "cilium"+transient+": any->cluster on "+localDeliveryInterface+" forward accept",
			"-j", "ACCEPT"), false); err != nil {
			return err
		}
		if err := runProg("iptables", append(
			m.waitArgs,
			"-A", forwardChain,
			"-i", localDeliveryInterface,
			"-m", "comment", "--comment", "cilium"+transient+": cluster->any on "+localDeliveryInterface+" forward accept (nodeport)",
			"-j", "ACCEPT"), false); err != nil {
			return err
		}
	}
	return nil
}

func (m *IptablesManager) installMasqueradeRules(prog, ifName, localDeliveryInterface,
	snatDstExclusionCIDR, allocRange, hostMasqueradeIP string) error {
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
	progArgs := append(
		m.waitArgs,
		"-t", "nat",
		"-A", ciliumPostNatChain,
		"!", "-d", snatDstExclusionCIDR,
	)

	if option.Config.EgressMasqueradeInterfaces != "" {
		progArgs = append(
			progArgs,
			"-o", option.Config.EgressMasqueradeInterfaces)
	} else {
		progArgs = append(
			progArgs,
			"-s", allocRange,
			"!", "-o", "cilium_+")
	}
	progArgs = append(
		progArgs,
		"-m", "comment", "--comment", "cilium masquerade non-cluster",
		"-j", "MASQUERADE")
	if option.Config.IPTablesRandomFully {
		progArgs = append(progArgs, "--random-fully")
	}
	if err := runProg(prog, progArgs, false); err != nil {
		return err
	}

	// The following rules exclude traffic from the remaining rules in this chain.
	// If any of these rules match, none of the remaining rules in this chain
	// are considered.
	// Exclude traffic for other than interface from the masquarade rules.
	// RETURN fro the chain as it is possible that other rules need to be matched.
	if err := runProg(prog, append(
		m.waitArgs,
		"-t", "nat",
		"-A", ciliumPostNatChain,
		"!", "-o", localDeliveryInterface,
		"-m", "comment", "--comment", "exclude non-"+ifName+" traffic from masquerade",
		"-j", "RETURN"), false); err != nil {
		return err
	}

	// Exclude proxy return traffic from the masquarade rules
	if err := runProg(prog, append(
		m.waitArgs,
		"-t", "nat",
		"-A", ciliumPostNatChain,
		// Don't match proxy (return) traffic
		"-m", "mark", "--mark", fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxy, linux_defaults.MagicMarkProxyMask),
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
		if err := runProg(prog, append(
			m.waitArgs,
			"-t", "nat",
			"-A", ciliumPostNatChain,
			"!", "-s", hostMasqueradeIP,
			"!", "-d", allocRange,
			"-o", "cilium_host",
			"-m", "comment", "--comment", "cilium host->cluster masquerade",
			"-j", "SNAT", "--to-source", hostMasqueradeIP), false); err != nil {
			return err
		}
	}

	loopbackAddr := "127.0.0.1"
	if prog == "ip6tables" {
		loopbackAddr = "::1"
	}

	// Masquerade all traffic from the host into local
	// endpoints if the source is 127.0.0.1. This is
	// required to force replies out of the endpoint's
	// network namespace.
	//
	// The following conditions must be met:
	// * Must be targeted for local endpoint
	// * Must be from 127.0.0.1
	if err := runProg(prog, append(
		m.waitArgs,
		"-t", "nat",
		"-A", ciliumPostNatChain,
		"-s", loopbackAddr,
		"-o", localDeliveryInterface,
		"-m", "comment", "--comment", "cilium host->cluster from "+loopbackAddr+" masquerade",
		"-j", "SNAT", "--to-source", hostMasqueradeIP), false); err != nil {
		return err
	}

	// Masquerade all traffic that originated from a local
	// pod and thus carries a security identity and that
	// was also DNAT'ed. It must be masqueraded to ensure
	// that reverse NAT can be performed. Otherwise the
	// reply traffic would be sent directly to the pod
	// without traversing the Linux stack again.
	//
	// This is only done if EnableEndpointRoutes is
	// disabled, if EnableEndpointRoutes is enabled, then
	// all traffic always passes through the stack anyway.
	//
	// This is required for:
	//  - portmap/host if both source and destination are
	//    on the same node
	//  - kiam if source and server are on the same node
	if !option.Config.EnableEndpointRoutes {
		if err := runProg(prog, append(
			m.waitArgs,
			"-t", "nat",
			"-A", ciliumPostNatChain,
			"-m", "mark", "--mark", fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIdentity, linux_defaults.MagicMarkHostMask),
			"-o", localDeliveryInterface,
			"-m", "conntrack", "--ctstate", "DNAT",
			"-m", "comment", "--comment", "hairpin traffic that originated from a local pod",
			"-j", "SNAT", "--to-source", hostMasqueradeIP), false); err != nil {
			return err
		}
	}

	return nil
}

func (m *IptablesManager) installHostTrafficMarkRule(prog string) error {
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
	matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
	matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)
	matchFromProxy := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxy, linux_defaults.MagicMarkProxyMask)
	markAsFromHost := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkHost, linux_defaults.MagicMarkHostMask)

	return runProg(prog, append(
		m.waitArgs,
		"-t", "filter",
		"-A", ciliumOutputChain,
		"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
		"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
		"-m", "mark", "!", "--mark", matchFromProxy, // Don't match proxy traffic
		"-m", "comment", "--comment", "cilium: host->any mark as from host",
		"-j", "MARK", "--set-xmark", markAsFromHost), false)
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
		if err := m.installForwardChainRules(ifName, localDeliveryInterface, transientChain.name); err != nil {
			return fmt.Errorf("cannot install forward chain rules to %s: %s", transientChain.name, err)
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
	for _, c := range ciliumChains {
		if err := c.add(m.waitArgs); err != nil {
			// do not return error for chain creation that are linked to disabled feeder rules
			skipFeeder := false
			for _, disabledChain := range option.Config.DisableIptablesFeederRules {
				if strings.EqualFold(c.hook, disabledChain) {
					skipFeeder = true
					break
				}
			}
			if skipFeeder {
				log.WithField("chain", c.name).Warningf("ignoring creation of chain since feeder rules for %s is disabled", c.hook)
				continue
			}

			return fmt.Errorf("cannot add custom chain %s: %s", c.name, err)
		}
	}

	if err := m.installStaticProxyRules(); err != nil {
		return fmt.Errorf("cannot add static proxy rules: %s", err)
	}

	if err := m.addCiliumAcceptXfrmRules(); err != nil {
		return err
	}

	localDeliveryInterface := getDeliveryInterface(ifName)

	if option.Config.EnableIPv4 {
		if err := m.installForwardChainRules(ifName, localDeliveryInterface, ciliumForwardChain); err != nil {
			return fmt.Errorf("cannot install forward chain rules to %s: %s", transientChain.name, err)
		}

		if err := m.installHostTrafficMarkRule("iptables"); err != nil {
			return err
		}

		if option.Config.EnableIPv4Masquerade && !option.Config.EnableBPFMasquerade {
			if err := m.installMasqueradeRules("iptables", ifName, localDeliveryInterface,
				datapath.RemoteSNATDstAddrExclusionCIDRv4().String(),
				node.GetIPv4AllocRange().String(),
				node.GetHostMasqueradeIPv4().String(),
			); err != nil {
				return err
			}
		}
	}

	if option.Config.EnableIPv6 {
		if err := m.installHostTrafficMarkRule("ip6tables"); err != nil {
			return err
		}

		if option.Config.EnableIPv6Masquerade && !option.Config.EnableBPFMasquerade {
			if err := m.installMasqueradeRules("ip6tables", ifName, localDeliveryInterface,
				datapath.RemoteSNATDstAddrExclusionCIDRv6().String(),
				node.GetIPv6AllocRange().String(),
				node.GetHostMasqueradeIPv6().String(),
			); err != nil {
				return err
			}
		}
	}

	// AWS ENI requires to mark packets ingressing on the primary interface
	// and route them back the same way even if the pod responding is using
	// the IP of a different interface. Please see note in Reinitialize()
	// in pkg/datapath/loader for more details.
	if option.Config.IPAM == ipamOption.IPAMENI {
		if err := m.addCiliumENIRules(); err != nil {
			return fmt.Errorf("cannot install rules for ENI multi-node NodePort: %w", err)
		}
	}

	if option.Config.EnableIPSec {
		if err := m.addCiliumNoTrackXfrmRules(); err != nil {
			return fmt.Errorf("cannot install xfrm rules: %s", err)
		}
	}

	for _, c := range ciliumChains {
		// do not install feeder for chains that are set to be disabled
		skipFeeder := false
		for _, disabledChain := range option.Config.DisableIptablesFeederRules {
			if strings.EqualFold(c.hook, disabledChain) {
				log.WithField("chain", c.hook).Infof("Skipping the install of feeder rule")
				skipFeeder = true
				break
			}
		}
		if skipFeeder {
			continue
		}

		if err := c.installFeeder(m.waitArgs); err != nil {
			return fmt.Errorf("cannot install feeder rule %s: %s", c.feederArgs, err)
		}
	}

	return nil
}

func (m *IptablesManager) ciliumNoTrackXfrmRules(prog, input string) error {
	matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
	matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)

	for _, match := range []string{matchFromIPSecDecrypt, matchFromIPSecEncrypt} {
		if err := runProg(prog, append(
			m.waitArgs,
			"-t", "raw", input, ciliumPreRawChain,
			"-m", "mark", "--mark", match,
			"-m", "comment", "--comment", xfrmDescription,
			"-j", "NOTRACK"), false); err != nil {
			return err
		}
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

func (m *IptablesManager) addCiliumENIRules() error {
	if !option.Config.EnableIPv4 {
		return nil
	}

	iface, err := route.NodeDeviceWithDefaultRoute(option.Config.EnableIPv4, option.Config.EnableIPv6)
	if err != nil {
		return fmt.Errorf("failed to find interface with default route: %w", err)
	}

	nfmask := fmt.Sprintf("%#08x", linux_defaults.MarkMultinodeNodeport)
	ctmask := fmt.Sprintf("%#08x", linux_defaults.MaskMultinodeNodeport)

	// Note: these rules need the xt_connmark module (iptables usually
	// loads it when required, unless loading modules after boot has been
	// disabled).
	if err := runProg("iptables", append(
		m.waitArgs,
		"-t", "mangle",
		"-A", ciliumPreMangleChain,
		"-i", iface.Attrs().Name,
		"-m", "comment", "--comment", "cilium: primary ENI",
		"-m", "addrtype", "--dst-type", "LOCAL", "--limit-iface-in",
		"-j", "CONNMARK", "--set-xmark", nfmask+"/"+ctmask),
		false); err != nil {
		return err
	}
	return runProg("iptables", append(
		m.waitArgs,
		"-t", "mangle",
		"-A", ciliumPreMangleChain,
		"-i", "lxc+",
		"-m", "comment", "--comment", "cilium: primary ENI",
		"-j", "CONNMARK", "--restore-mark", "--nfmask", nfmask, "--ctmask", ctmask),
		false)
}

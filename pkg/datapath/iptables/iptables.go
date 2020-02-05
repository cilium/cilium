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
	"sync"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/modules"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/versioncheck"

	go_version "github.com/blang/semver"
	"github.com/mattn/go-shellwords"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	ciliumPrefix          = "CILIUM_"
	ciliumInputChain      = "CILIUM_INPUT"
	ciliumOutputChain     = "CILIUM_OUTPUT"
	ciliumOutputRawChain  = "CILIUM_OUTPUT_raw"
	ciliumPostNatChain    = "CILIUM_POST_nat"
	ciliumOutputNatChain  = "CILIUM_OUTPUT_nat"
	ciliumPreNatChain     = "CILIUM_PRE_nat"
	ciliumPostMangleChain = "CILIUM_POST_mangle"
	ciliumPreMangleChain  = "CILIUM_PRE_mangle"
	ciliumPreRawChain     = "CILIUM_PRE_raw"
	ciliumForwardChain    = "CILIUM_FORWARD"
	feederDescription     = "cilium-feeder:"
	xfrmDescription       = "cilium-xfrm-notrack:"
)

// Minimum iptables versions supporting the -w and -w<seconds> flags
var (
	isWaitMinVersion        = versioncheck.MustCompile(">=1.4.20")
	isWaitSecondsMinVersion = versioncheck.MustCompile(">=1.4.22")
	hexnumRE                = regexp.MustCompile("0x0+([0-9])")
)

const (
	waitString       = "-w"
	waitSecondsValue = "5"
)

type operation string

const (
	opCreateChain operation = "-N"
	opFlushChain  operation = "-F"
	opDeleteChain operation = "-X"
	opCheckRule   operation = "-C"
	opInsertRule  operation = "-I"
	opAppendRule  operation = "-A"
)

// exitError is the error interface for exec commands.
type exitError interface {
	Exited() bool
	ExitStatus() int
}

type iptablesRule struct {
	args            []string
	enabled         bool
	ipv4Only        bool
	needSocketMatch bool
}

func newIptablesRule(args []string, enabled, ipv4Only, needSocketMatch bool) iptablesRule {
	return iptablesRule{
		args,
		enabled,
		ipv4Only,
		needSocketMatch,
	}
}

type customChain struct {
	name       string
	table      string
	hook       string
	feederArgs []string
	ipv6       bool // ip6tables chain in addition to iptables chain
}

func getVersion(prog string) (go_version.Version, error) {
	b, err := exec.WithTimeout(defaults.ExecTimeout, prog, "--version").CombinedOutput(log, false)
	if err != nil {
		return go_version.Version{}, err
	}
	v := regexp.MustCompile("v([0-9]+(\\.[0-9]+)+)")
	vString := v.FindStringSubmatch(string(b))
	if vString == nil {
		return go_version.Version{}, fmt.Errorf("no iptables version found in string: %s", string(b))
	}
	return versioncheck.Version(vString[1])
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

// Exclude crypto traffic from the filter and nat table rules.
// This avoids encryption bits and keyID, 0x*d00 for decryption
// and 0x*e00 for encryption, colliding with existing rules. Needed
// for kube-proxy for example.
func ciliumAcceptXfrmRules(table, chain string) []iptablesRule {
	matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
	matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)

	xfrmComment := "exclude xfrm marks from filter " + chain + " chain"
	return []iptablesRule{
		newIptablesRule([]string{
			"-t", table,
			"-m", "mark", "--mark", matchFromIPSecEncrypt,
			"-m", "comment", "--comment", xfrmComment,
			"-j", "ACCEPT",
		}, option.Config.EnableIPSec, true, false),

		newIptablesRule([]string{
			"-t", table,
			"-m", "mark", "--mark", matchFromIPSecDecrypt,
			"-m", "comment", "--comment", xfrmComment,
			"-j", "ACCEPT",
		}, option.Config.EnableIPSec, true, false),
	}
}

func ciliumInputChainRules() []iptablesRule {
	// match traffic to a proxy (upper 16 bits has the proxy port, which is masked out)
	matchToProxy := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsToProxy, linux_defaults.MagicMarkHostMask)

	return append(
		[]iptablesRule{
			newIptablesRule([]string{
				"-t", "filter",
				// Destination is a local node POD address
				"!", "-d", node.GetInternalIPv4().String(),
				"-m", "mark", "--mark", matchToProxy,
				"-m", "comment", "--comment", "cilium: ACCEPT for proxy traffic",
				"-j", "ACCEPT",
			}, true, false, false),
		},

		// CiliumAcceptXfrmRules
		ciliumAcceptXfrmRules("filter", ciliumInputChain)...,
	)
}

func ciliumOutputChainRules() []iptablesRule {
	// proxy return traffic has 0 ID in the mask
	matchProxyReply := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxy, linux_defaults.MagicMarkProxyNoIDMask)

	matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
	matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)
	markAsFromHost := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkHost, linux_defaults.MagicMarkHostMask)
	matchFromProxy := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxy, linux_defaults.MagicMarkProxyMask)

	return append(
		[]iptablesRule{
			newIptablesRule([]string{
				"-t", "filter",
				// Return traffic is from a local node POD address
				"!", "-s", node.GetInternalIPv4().String(),
				"-m", "mark", "--mark", matchProxyReply,
				"-m", "comment", "--comment", "cilium: ACCEPT for proxy return traffic",
				"-j", "ACCEPT",
			}, true, false, false),
		},

		append(
			// CiliumAcceptXfrmRules
			ciliumAcceptXfrmRules("filter", ciliumOutputChain),

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
			newIptablesRule([]string{
				"-t", "filter",
				"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
				"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
				"-m", "mark", "!", "--mark", matchFromProxy, // Don't match proxy traffic
				"-m", "comment", "--comment", "cilium: host->any mark as from host",
				"-j", "MARK", "--set-xmark", markAsFromHost,
			}, true, true, false),
		)...,
	)
}

func ciliumOutputRawChainRules() []iptablesRule {
	// proxy return traffic has 0 ID in the mask
	matchProxyReply := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxy, linux_defaults.MagicMarkProxyNoIDMask)

	return []iptablesRule{
		newIptablesRule([]string{
			"-t", "raw",
			// Return traffic is from a local node POD address
			"!", "-s", node.GetInternalIPv4().String(),
			"-m", "mark", "--mark", matchProxyReply,
			"-m", "comment", "--comment", "cilium: NOTRACK for proxy return traffic",
			"-j", "NOTRACK",
		}, true, false, false),
	}
}

func ciliumPostNatChainRules(m *IptablesManager, ifName string) []iptablesRule {
	localDeliveryInterface := getDeliveryInterface(ifName)
	matchFromProxy := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsProxy, linux_defaults.MagicMarkProxyMask)

	return append(
		ciliumAcceptXfrmRules("nat", ciliumPostNatChain),

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
		newIptablesRule([]string{
			"-t", "nat",
			"!", "-d", m.remoteSnatDstAddrExclusion(),
			"-o", option.Config.EgressMasqueradeInterfaces,
			"-m", "comment", "--comment", "cilium masquerade non-cluster",
			"-j", "MASQUERADE",
		},
			option.Config.Masquerade && option.Config.EgressMasqueradeInterfaces != "",
			true, false),

		newIptablesRule([]string{
			"-t", "nat",
			"-s", node.GetIPv4AllocRange().String(),
			"!", "-d", m.remoteSnatDstAddrExclusion(),
			"!", "-o", "cilium_+",
			"-m", "comment", "--comment", "cilium masquerade non-cluster",
			"-j", "MASQUERADE",
		},
			option.Config.Masquerade && option.Config.EgressMasqueradeInterfaces == "",
			true, false),

		// The following rules exclude traffic from the remaining rules in this chain.
		// If any of these rules match, none of the remaining rules in this chain
		// are considered.
		// Exclude traffic for other than interface from the masquarade rules.
		// RETURN fro the chain as it is possible that other rules need to be matched.
		newIptablesRule([]string{
			"-t", "nat",
			"!", "-o", localDeliveryInterface,
			"-m", "comment", "--comment", "exclude non-" + ifName + " traffic from masquerade",
			"-j", "RETURN",
		}, option.Config.Masquerade, true, false),

		// Exclude proxy return traffic from the masquarade rules
		newIptablesRule([]string{
			"-t", "nat",
			"-m", "mark", "--mark", matchFromProxy, // Don't match proxy (return) traffic
			"-m", "comment", "--comment", "exclude proxy return traffic from masquarade",
			"-j", "ACCEPT",
		}, option.Config.Masquerade, true, false),

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
		newIptablesRule([]string{
			"-t", "nat",
			"!", "-s", node.GetHostMasqueradeIPv4().String(),
			"!", "-d", node.GetIPv4AllocRange().String(),
			"-o", "cilium_host",
			"-m", "comment", "--comment", "cilium host->cluster masquerade",
			"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String(),
		},
			option.Config.Masquerade && option.Config.Tunnel != option.TunnelDisabled,
			true, false),

		// Masquerade all traffic from the host into local
		// endpoints if the source is 127.0.0.1. This is
		// required to force replies out of the endpoint's
		// network namespace.
		//
		// The following conditions must be met:
		// * Must be targeted for local endpoint
		// * Must be from 127.0.0.1
		newIptablesRule([]string{
			"-t", "nat",
			"-s", "127.0.0.1",
			"-o", localDeliveryInterface,
			"-m", "comment", "--comment", "cilium host->cluster from 127.0.0.1 masquerade",
			"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String(),
		}, option.Config.Masquerade, true, false),
	)
}

func ciliumOutputNatChainRules() []iptablesRule {
	return ciliumAcceptXfrmRules("nat", ciliumOutputNatChain)
}

func ciliumPreNatChainRules() []iptablesRule {
	return ciliumAcceptXfrmRules("nat", ciliumPreNatChain)
}

func ciliumPostMangleChainRules() []iptablesRule {
	return []iptablesRule{}
}

func ciliumPreMangleChainRules() []iptablesRule {
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

	return []iptablesRule{
		// This is for inboundProxyRedirectRule
		newIptablesRule([]string{
			"-t", "mangle",
			"-m", "socket", "--transparent", "--nowildcard",
			"-m", "comment", "--comment", "cilium: any->pod redirect proxied traffic to host proxy",
			"-j", "MARK",
			"--set-mark", toProxyMark,
		}, true, false, true),
	}
}

func ciliumPreRawChainRules() []iptablesRule {
	// match traffic to a proxy (upper 16 bits has the proxy port, which is masked out)
	matchToProxy := fmt.Sprintf("%#08x/%#08x", linux_defaults.MagicMarkIsToProxy, linux_defaults.MagicMarkHostMask)

	matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
	matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)

	return []iptablesRule{
		newIptablesRule([]string{
			"-t", "raw",
			"-m", "mark", "--mark", matchFromIPSecEncrypt,
			"-m", "comment", "--comment", xfrmDescription,
			"-j", "NOTRACK",
		}, option.Config.EnableIPSec, true, false),

		newIptablesRule([]string{
			"-t", "raw",
			"-m", "mark", "--mark", matchFromIPSecDecrypt,
			"-m", "comment", "--comment", xfrmDescription,
			"-j", "NOTRACK",
		}, option.Config.EnableIPSec, true, false),

		newIptablesRule([]string{
			"-t", "raw",
			// Destination is a local node POD address
			"!", "-d", node.GetInternalIPv4().String(),
			"-m", "mark", "--mark", matchToProxy,
			"-m", "comment", "--comment", "cilium: NOTRACK for proxy traffic",
			"-j", "NOTRACK",
		}, true, false, false),
	}
}

func ciliumForwardChainRules(ifName string) []iptablesRule {
	localDeliveryInterface := getDeliveryInterface(ifName)

	return append(
		ciliumAcceptXfrmRules("filter", ciliumForwardChain),

		newIptablesRule([]string{
			"-t", "filter",
			"-o", localDeliveryInterface,
			"-m", "comment", "--comment", "cilium: any->cluster on " + localDeliveryInterface + " forward accept",
			"-j", "ACCEPT",
		}, true, true, false),

		newIptablesRule([]string{
			"-t", "filter",
			"-i", localDeliveryInterface,
			"-m", "comment", "--comment", "cilium: cluster->any on " + localDeliveryInterface + " forward accept (nodeport)",
			"-j", "ACCEPT",
		}, true, true, false),

		newIptablesRule([]string{
			"-t", "filter",
			"-i", "lxc+",
			"-m", "comment", "--comment", "cilium: cluster->any on lxc+ forward accept",
			"-j", "ACCEPT",
		}, true, true, false),
	)
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

// IptablesManager manages the iptables-related configuration for Cilium.
type IptablesManager struct {
	haveIp6tables   bool
	haveSocketMatch bool
	waitArgs        []string

	mu sync.Mutex
}

// Init initializes the iptables manager and checks for iptables kernel modules
// availability.
func (m *IptablesManager) Init() {
	modulesManager := &modules.ModulesManager{}
	ip6tables := true

	m.mu.Lock()
	defer m.mu.Unlock()
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
		case isWaitSecondsMinVersion(v):
			m.waitArgs = []string{waitString, waitSecondsValue}
		case isWaitMinVersion(v):
			m.waitArgs = []string{waitString}
		}
	}
}

func (m *IptablesManager) runProg(prog string, args []string, quiet bool) ([]byte, error) {
	fullArgs := append(m.waitArgs, args...)

	log.WithField(logfields.IptablesCmd,
		fmt.Sprintf("%s %v", prog, fullArgs)).Debug("executing iptables")
	return exec.WithTimeout(defaults.ExecTimeout, prog, args...).CombinedOutput(log, !quiet)
}

func (m *IptablesManager) ensureChain(c *customChain, prog string) error {
	fullArgs := []string{string(opCreateChain), string(c.name), "-t", string(c.table)}

	out, err := m.runProg(prog, fullArgs, false)

	if err != nil {
		if ee, ok := err.(exitError); ok {
			if ee.Exited() && ee.ExitStatus() == 1 {
				return nil
			}
		}
		return fmt.Errorf("error creating chain %q: %v: %s", c.name, err, out)
	}
	return nil
}

// ensureChains ensures that the chains that are managed by cilium are present and are associated
// with the required hooks.
func (m *IptablesManager) ensureCiliumChains() error {
	var err error
	for _, c := range ciliumChains {
		if option.Config.EnableIPv4 {
			err = m.ensureChain(&c, "iptables")
		}
		if err == nil && option.Config.EnableIPv6 && c.ipv6 == true {
			err = m.ensureChain(&c, "ip6tables")
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (m *IptablesManager) filterRuleSet(rules []iptablesRule) []iptablesRule {
	retRules := []iptablesRule{}
	for _, rule := range rules {
		if rule.enabled {
			retRules = append(retRules, rule)
		}
	}

	return retRules
}

func (m *IptablesManager) checkRule(prog, chain string, rule iptablesRule) (bool, error) {
	checkArgs := append([]string{string(opCheckRule), chain}, rule.args...)
	out, err := m.runProg(prog, checkArgs, false)
	if err == nil {
		return true, nil
	}
	if ee, ok := err.(exitError); ok {
		// If the error code 1 iptables indicates that there is a failure
		// in the operation as opposed to being malformed commandline.
		if ee.Exited() && ee.ExitStatus() == 1 {
			return false, nil
		}
	}
	return false, fmt.Errorf("error chcking rule %v: %v: %s", rule.args, err, out)
}

func (m *IptablesManager) ensureIptRules(prog, table, chain string, rules []iptablesRule) error {
	rulesCount := len(rules)
	if rulesCount == 0 {
		return nil
	}

	curRuleIndex := 0
	var ruleArgsCopy []string
	for i := range rules[curRuleIndex].args {
		tmpField := strings.Trim(rules[curRuleIndex].args[i], "\"")
		tmpField = hexnumRE.ReplaceAllString(tmpField, "0x$1")
		ruleArgsCopy = append(ruleArgsCopy, strings.Fields(tmpField)...)
	}
	ruleArgset := sets.NewString(ruleArgsCopy...)

	// Collect output from ipables-save command so that we can cross verify the rules that
	// exists.
	// We are not using iptables -C flag because we also want to preserve the order or the rules
	// which won't be possible with -C as there is possibly no way of knowing what position
	// a rule exists in.
	args := append(m.waitArgs, "-t", table, "-S")

	out, err := exec.WithTimeout(defaults.ExecTimeout, prog, args...).CombinedOutput(log, true)
	if err != nil {
		return fmt.Errorf("error while getting iptables save output: %s", err)
	}

	iptablesSaveOutput := strings.Split(string(out), "\n")
	existingRulesCount := len(iptablesSaveOutput)

	idx := 0
	for idx < existingRulesCount {
		line := iptablesSaveOutput[idx]
		// First check if this corresponds to an insert rule of cilium in the correct chain
		// name we are trying to ensure.
		// If not move on to the next line.
		if !strings.HasPrefix(line, fmt.Sprintf("%s %s", string(opInsertRule), chain)) {
			idx++
			continue
		}

		if curRuleIndex >= rulesCount {
			// We have ensured all the rules, delete all unnecessery rules
			reversedRule, err := reverseRule(line)
			if err != nil {
				log.WithError(err).WithField(logfields.Object, line).Warnf("Unable to parse %s rule into slice. Leaving rule behind.", prog)
			} else if len(reversedRule) > 0 {
				deleteRule := append([]string{"-t", table}, reversedRule...)
				log.WithField(logfields.Object, logfields.Repr(deleteRule)).Debugf("Removing %s rule", prog)
				_, err = m.runProg(prog, deleteRule, true)
				if err != nil {
					log.WithError(err).WithField(logfields.Object, line).Warnf("Unable to delete Cilium %s rule", prog)
				}
			}

			idx++
			continue
		}

		// Iptables has inconsistent quoting rules for comments.
		// Just remove all quotes.
		var fields = strings.Fields(line)
		for i := range fields {
			fields[i] = strings.Trim(fields[i], "\"")
			fields[i] = hexnumRE.ReplaceAllString(fields[i], "0x$1")
		}

		// From https://github.com/kubernetes/kubernetes/blob/master/pkg/util/iptables/iptables.go
		// TODO: This misses reorderings e.g. "-x foo ! -y bar" will match "! -x foo -y bar"
		if sets.NewString(fields...).IsSuperset(ruleArgset) {
			// This means that the rule exists and is at the right position as we are iterating from
			// top to down for the rules.
			curRuleIndex++
			idx++

			// Process the next rule in the list.
			var argsCopy []string
			for i := range rules[curRuleIndex].args {
				tmpField := strings.Trim(rules[curRuleIndex].args[i], "\"")
				tmpField = hexnumRE.ReplaceAllString(tmpField, "0x$1")
				argsCopy = append(argsCopy, strings.Fields(tmpField)...)
			}
			ruleArgset = sets.NewString(argsCopy...)
		} else {
			// Insert the rule we are currently working in the ruleset to ensure.
			insertArgs := append([]string{string(opInsertRule), chain, string(curRuleIndex)}, rules[curRuleIndex].args...)
			out, err := m.runProg("iptables", insertArgs, false)
			if err != nil {
				return fmt.Errorf("error inserting rule: %s : %s", err, out)
			}

			curRuleIndex++
		}
	}

	return nil
}

func (m *IptablesManager) ensureChainRules(table, chainName string, rules []iptablesRule) error {
	if option.Config.EnableIPv4 {
		err := m.ensureIptRules("iptables", table, chainName, rules)
		if err != nil {
			return err
		}
	}

	if option.Config.EnableIPv6 {
		var ipv6EnabledRules []iptablesRule

		for _, rule := range rules {
			if !rule.ipv4Only {
				ipv6EnabledRules = append(ipv6EnabledRules, rule)
			}
		}

		return m.ensureIptRules("ip6tables", table, chainName, ipv6EnabledRules)
	}

	return nil
}

// EnsureRules ensures that the iptable rules managed by Cilium are present and are
// in the right order. If a rule is missing from the chain, cilium reinstall only
// that particular iptable rule.
//
// Insert syntax for iptables is of the following format
// sudo iptables -I [chain] [rule-number] [rule]
func (m *IptablesManager) EnsureRules(ifname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureCiliumChains(); err != nil {
		return err
	}

	// All the rules must be prepended with the operation to perform on the iptable
	// rule and then run using an iptable program. Since we are relying on inserts
	inputChainRules := m.filterRuleSet(ciliumInputChainRules())
	err := m.ensureChainRules("filter", ciliumInputChain, inputChainRules)
	if err != nil {
		return err
	}

	outputChainRules := m.filterRuleSet(ciliumOutputChainRules())
	err = m.ensureChainRules("filter", ciliumOutputChain, outputChainRules)
	if err != nil {
		return err
	}

	outputRawChainRules := m.filterRuleSet(ciliumOutputRawChainRules())
	err = m.ensureChainRules("raw", ciliumOutputRawChain, outputRawChainRules)
	if err != nil {
		return err
	}

	postNatChainRules := m.filterRuleSet(ciliumPostNatChainRules(m, ifname))
	err = m.ensureChainRules("nat", ciliumPostNatChain, postNatChainRules)
	if err != nil {
		return err
	}

	outputNatChainRules := m.filterRuleSet(ciliumOutputNatChainRules())
	err = m.ensureChainRules("nat", ciliumOutputNatChain, outputNatChainRules)
	if err != nil {
		return err
	}

	preNatChainRules := m.filterRuleSet(ciliumPreNatChainRules())
	err = m.ensureChainRules("nat", ciliumPreNatChain, preNatChainRules)
	if err != nil {
		return err
	}

	postMangleChainRules := m.filterRuleSet(ciliumPostMangleChainRules())
	err = m.ensureChainRules("mangle", ciliumPostMangleChain, postMangleChainRules)
	if err != nil {
		return err
	}

	preMangleChainRules := m.filterRuleSet(ciliumPreMangleChainRules())
	err = m.ensureChainRules("mangle", ciliumPreMangleChain, preMangleChainRules)
	if err != nil {
		return err
	}

	preRawChainRules := m.filterRuleSet(ciliumPreRawChainRules())
	err = m.ensureChainRules("raw", ciliumPreRawChain, preRawChainRules)
	if err != nil {
		return err
	}

	forwardChainRules := m.filterRuleSet(ciliumForwardChainRules(ifname))
	err = m.ensureChainRules("filter", ciliumForwardChain, forwardChainRules)
	if err != nil {
		return err
	}

	return nil
}

func (m *IptablesManager) SupportsOriginalSourceAddr() bool {
	return m.haveSocketMatch
}

// removeCiliumRules removes the iptable rules in the requested table associated
// with the chain specified by match.
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
				deleteRule := append([]string{"-t", table}, reversedRule...)
				log.WithField(logfields.Object, logfields.Repr(deleteRule)).Debugf("Removing %s rule", prog)
				_, err = m.runProg(prog, deleteRule, true)
				if err != nil {
					log.WithError(err).WithField(logfields.Object, rule).Warnf("Unable to delete Cilium %s rule", prog)
				}
			}
		}
	}
}

func (m *IptablesManager) removeChain(c *customChain, prog string) {
	fullFlushArgs := []string{string(opFlushChain), string(c.name), "-t", string(c.table)}
	fullRemoveArgs := []string{string(opDeleteChain), string(c.name), "-t", string(c.table)}

	_, err := m.runProg(prog, fullFlushArgs, false)
	if err != nil {
		log.WithError(err).WithField(logfields.Object, fullFlushArgs).Warnf("Unable to flush Cilium %s chain", prog)
	}

	_, err = m.runProg(prog, fullRemoveArgs, false)
	if err != nil {
		log.WithError(err).WithField(logfields.Object, fullRemoveArgs).Warnf("Unable to delete Cilium %s chain", prog)
	}
}

func (m *IptablesManager) removeCiliumChains() {
	for _, c := range ciliumChains {
		if option.Config.EnableIPv4 {
			m.removeChain(&c, "iptables")
		}
		if option.Config.EnableIPv6 && c.ipv6 == true {
			m.removeChain(&c, "ip6tables")
		}
	}
}

// RemoveRules removes iptables rules installed by Cilium.
func (m *IptablesManager) RemoveRules() {
	m.mu.Lock()
	defer m.mu.Unlock()

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

	m.removeCiliumChains()
}

func (m *IptablesManager) ingressProxyRule(cmd, l4Match, markMatch, mark, port, name string) []string {
	return []string{
		"-t", "mangle",
		cmd, ciliumPreMangleChain,
		"-p", l4Match,
		"-m", "mark", "--mark", markMatch,
		"-m", "comment", "--comment", "cilium: TPROXY to host " + name + " proxy",
		"-j", "TPROXY",
		"--tproxy-mark", mark,
		"--on-port", port,
	}
}

func (m *IptablesManager) iptIngressProxyRule(cmd string, l4proto string, proxyPort uint16, name string) error {
	// Match
	port := uint32(byteorder.HostToNetwork(proxyPort).(uint16)) << 16
	ingressMarkMatch := fmt.Sprintf("%#08x", linux_defaults.MagicMarkIsToProxy|port)
	// TPROXY params
	ingressProxyMark := fmt.Sprintf("%#08x", linux_defaults.MagicMarkIsToProxy)
	ingressProxyPort := fmt.Sprintf("%d", proxyPort)

	var err error
	m.mu.Lock()
	defer m.mu.Unlock()
	if option.Config.EnableIPv4 {
		_, err = m.runProg("iptables",
			m.ingressProxyRule(cmd, l4proto, ingressMarkMatch,
				ingressProxyMark, ingressProxyPort, name),
			false)
	}
	if err == nil && option.Config.EnableIPv6 {
		_, err = m.runProg("ip6tables",
			m.ingressProxyRule(cmd, l4proto, ingressMarkMatch,
				ingressProxyMark, ingressProxyPort, name),
			false)
	}
	return err
}

func (m *IptablesManager) egressProxyRule(cmd, l4Match, markMatch, mark, port, name string) []string {
	return []string{
		"-t", "mangle",
		cmd, ciliumPreMangleChain,
		"-p", l4Match,
		"-m", "mark", "--mark", markMatch,
		"-m", "comment", "--comment", "cilium: TPROXY to host " + name + " proxy",
		"-j", "TPROXY",
		"--tproxy-mark", mark,
		"--on-port", port,
	}
}

func (m *IptablesManager) iptEgressProxyRule(cmd string, l4proto string, proxyPort uint16, name string) error {
	// Match
	port := uint32(byteorder.HostToNetwork(proxyPort).(uint16)) << 16
	egressMarkMatch := fmt.Sprintf("%#08x", linux_defaults.MagicMarkIsToProxy|port)
	// TPROXY params
	egressProxyMark := fmt.Sprintf("%#08x", linux_defaults.MagicMarkIsToProxy)
	egressProxyPort := fmt.Sprintf("%d", proxyPort)

	var err error
	m.mu.Lock()
	defer m.mu.Unlock()
	if option.Config.EnableIPv4 {
		_, err = m.runProg("iptables",
			m.egressProxyRule(cmd, l4proto, egressMarkMatch,
				egressProxyMark, egressProxyPort, name),
			false)
	}
	if err == nil && option.Config.EnableIPv6 {
		_, err = m.runProg("ip6tables",
			m.egressProxyRule(cmd, l4proto, egressMarkMatch,
				egressProxyMark, egressProxyPort, name),
			false)
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

// InstallProxyRules installs cilium proxy iptables rules.
func (m *IptablesManager) InstallProxyRules(proxyPort uint16, ingress bool, name string) error {
	return m.iptProxyRules("-A", proxyPort, ingress, name)
}

// RemoveProxyRules removes the cilium installed iptables rules for proxy.
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

func (m *IptablesManager) installFeeder(c *customChain) error {
	installMode := "-A"
	if option.Config.PrependIptablesChains {
		installMode = "-I"
	}

	for _, feedArgs := range c.feederArgs {
		if option.Config.EnableIPv4 {
			_, err := m.runProg("iptables", append([]string{"-t", c.table, installMode, c.hook},
				getFeedRule(c.name, feedArgs)...), true)
			if err != nil {
				return err
			}
		}
		if option.Config.EnableIPv6 && c.ipv6 == true {
			_, err := m.runProg("ip6tables", append([]string{"-t", c.table, installMode, c.hook},
				getFeedRule(c.name, feedArgs)...), true)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// InstallRules installs iptables rules for Cilium in specific use-cases
// (most specifically, interaction with kube-proxy).
func (m *IptablesManager) InstallRules(ifName string) error {
	if err := m.EnsureRules(ifName); err != nil {
		return err
	}

	for _, c := range ciliumChains {
		if err := m.installFeeder(&c); err != nil {
			return fmt.Errorf("cannot install feeder rule %s: %s", c.feederArgs, err)
		}
	}

	return nil
}

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

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/modules"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/versioncheck"

	go_version "github.com/hashicorp/go-version"
	"github.com/mattn/go-shellwords"
)

const (
	ciliumPrefix                = "CILIUM_"
	ciliumInputChain            = "CILIUM_INPUT"
	ciliumOutputChain           = "CILIUM_OUTPUT"
	ciliumOutputRawChain        = "CILIUM_OUTPUT_raw"
	ciliumPostNatKubeChain      = "CILIUM_POST_KUBE"
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
	name        string
	table       string
	hook        string
	feederArgs  []string
	ipv6        bool // ip6tables chain in addition to iptables chain
	appendFixed bool
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

func (c *customChain) remove(waitArgs []string) {
	if option.Config.EnableIPv4 {
		runProg("iptables", append(
			waitArgs,
			"-t", c.table,
			"-F", c.name), true)

		runProg("iptables", append(
			waitArgs,
			"-t", c.table,
			"-X", c.name), true)
	}
	if option.Config.EnableIPv6 && c.ipv6 == true {
		runProg("ip6tables", append(
			waitArgs,
			"-t", c.table,
			"-F", c.name), true)

		runProg("ip6tables", append(
			waitArgs,
			"-t", c.table,
			"-X", c.name), true)
	}
}

func (c *customChain) installFeeder(waitArgs []string) error {
	installMode := "-A"
	if option.Config.PrependIptablesChains && !c.appendFixed {
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
	},

	{
		name:       ciliumOutputChain,
		table:      "filter",
		hook:       "OUTPUT",
		feederArgs: []string{""},
	},
	{
		name:       ciliumPostNatChain,
		table:      "nat",
		hook:       "POSTROUTING",
		feederArgs: []string{""},
	},
	{
		name:        ciliumPostNatKubeChain,
		table:       "nat",
		hook:        "POSTROUTING",
		feederArgs:  []string{""},
		ipv6:        true,
		appendFixed: true,
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
		name:       ciliumPreRawChain,
		table:      "raw",
		hook:       "PREROUTING",
		feederArgs: []string{""},
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
	ip6tables bool
	waitArgs  []string
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
		"ip6_tables", "ip6table_mangle", "ip6table_raw"); err != nil {
		if option.Config.EnableIPv6 {
			log.WithError(err).Warning(
				"IPv6 is enabled and ip6tables modules could not be initialized")
		}
		log.WithError(err).Debug(
			"ip6tables kernel modules could not be loaded, so IPv6 cannot be used")
		ip6tables = false
	}
	m.ip6tables = ip6tables

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

// RemoveRules removes iptables rules installed by Cilium.
func (m *IptablesManager) RemoveRules() {
	// Set of tables that have had iptables rules in any Cilium version
	tables := []string{"nat", "mangle", "raw", "filter"}
	for _, t := range tables {
		m.removeCiliumRules(t, "iptables", ciliumPrefix)
	}

	// Set of tables that have had ip6tables rules in any Cilium version
	if m.ip6tables {
		tables6 := []string{"nat", "mangle", "raw"}
		for _, t := range tables6 {
			m.removeCiliumRules(t, "ip6tables", ciliumPrefix)
		}
	}

	for _, c := range ciliumChains {
		c.remove(m.waitArgs)
	}
}

// TransientRulesStart installs iptables rules for Cilium that need to be
// kept in-tact during agent restart which removes/installs its main rules.
// Transient rules are then removed once iptables rule update cycle has
// completed. This is mainly due to interactions with kube-proxy.
func (m *IptablesManager) TransientRulesStart(ifName string) error {
	if option.Config.EnableIPv4 {
		m.TransientRulesEnd()

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
			"-o", ifName,
			"-m", "comment", "--comment", "cilium (transient): any->cluster on "+ifName+" forward accept",
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
func (m *IptablesManager) TransientRulesEnd() {
	if option.Config.EnableIPv4 {
		m.removeCiliumRules("filter", "iptables", ciliumTransientForwardChain)
		transientChain.remove(m.waitArgs)
	}
}

// InstallRules installs iptables rules for Cilium in specific use-cases
// (most specifically, interaction with kube-proxy).
func (m *IptablesManager) InstallRules(ifName string) error {
	for _, c := range ciliumChains {
		if err := c.add(m.waitArgs); err != nil {
			return fmt.Errorf("cannot add custom chain %s: %s", c.name, err)
		}
	}

	if option.Config.EnableIPv4 {
		matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
		matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)

		// Clear the Kubernetes masquerading mark bit to skip source PAT
		// performed by kube-proxy for all packets destined for Cilium. Cilium
		// installs a dedicated rule which does the source PAT to the right
		// source IP.
		clearMasqBit := fmt.Sprintf("%#08x/%#08x", 0, proxy.MagicMarkK8sMasq)
		if err := runProg("iptables", append(
			m.waitArgs,
			"-t", "mangle",
			"-A", ciliumPostMangleChain,
			"-o", ifName,
			"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
			"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
			"-m", "comment", "--comment", "cilium: clear masq bit for pkts to "+ifName,
			"-j", "MARK", "--set-xmark", clearMasqBit), false); err != nil {
			return err
		}

		// See kube-proxy comment in TransientRules().
		if err := runProg("iptables", append(
			m.waitArgs,
			"-A", ciliumForwardChain,
			"-o", ifName,
			"-m", "comment", "--comment", "cilium: any->cluster on "+ifName+" forward accept",
			"-j", "ACCEPT"), false); err != nil {
			return err
		}

		// Accept all packets in the FORWARD chain that are coming from the
		// ifName interface with a source IP in the local node
		// allocation range.
		if err := runProg("iptables", append(
			m.waitArgs,
			"-A", ciliumForwardChain,
			"-s", node.GetIPv4AllocRange().String(),
			"-m", "comment", "--comment", "cilium: cluster->any forward accept",
			"-j", "ACCEPT"), false); err != nil {
			return err
		}

		// For communication from host to local services via k8s cluster IP
		// we need to fix up wrong source address selection. Linux routing
		// will initially select a source address based on the service IP and
		// after Kubernetes iptables rules selected a local backend, we still
		// retain the original source address (and not the one on cilium_host).
		// As a result, ipcache will assign a WORLD identity (via catch-all 0/0)
		// as opposed to a HOST identity and therefore policy is dropping the
		// skb. As there is no fixup by iptables, we need to SNAT for these
		// cases. This rule here must come after all Kubernetes post-routing
		// chains, so we can match on our endpoint allocation range.
		if option.Config.EnableIPv4 {
			if err := runProg("iptables", append(
				m.waitArgs,
				"-t", "nat",
				"-A", ciliumPostNatKubeChain,
				"-d", node.GetIPv4AllocRange().String(),
				"-o", ifName,
				"-m", "comment", "--comment", "cilium: host->service(cluster ip)->local-endpoint on "+ifName+" src address fix",
				"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()), false); err != nil {
				return err
			}
		}
		if option.Config.EnableIPv6 {
			if err := runProg("ip6tables", append(
				m.waitArgs,
				"-t", "nat",
				"-A", ciliumPostNatKubeChain,
				"-d", node.GetIPv6AllocRange().String(),
				"-o", ifName,
				"-m", "comment", "--comment", "cilium: host->service(cluster ip)->local-endpoint on "+ifName+" src address fix",
				"-j", "SNAT", "--to-source", node.GetIPv6().String()), false); err != nil {
				return err
			}
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
		matchFromProxy := fmt.Sprintf("%#08x/%#08x", proxy.MagicMarkIsProxy, proxy.MagicMarkProxyMask)
		markAsFromHost := fmt.Sprintf("%#08x/%#08x", proxy.MagicMarkHost, proxy.MagicMarkHostMask)
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
			ingressSnatSrcAddrExclusion := node.GetHostMasqueradeIPv4().String()
			if option.Config.Tunnel == option.TunnelDisabled {
				ingressSnatSrcAddrExclusion = node.GetIPv4ClusterRange().String()
			}

			egressSnatDstAddrExclusion := node.GetIPv4AllocRange().String()
			if option.Config.Tunnel == option.TunnelDisabled {
				egressSnatDstAddrExclusion = node.GetIPv4ClusterRange().String()
			}

			// Masquerade all egress traffic leaving the node
			//
			// This rule must be first as it has different exclusion criteria
			// than the other rules in this table.
			//
			// The following conditions must be met:
			// * May not leave on a cilium_ interface, this excludes all
			//   tunnel traffic
			// * Must originate from an IP in the local allocation range
			// * Tunnel mode:
			//   * May not be targeted to an IP in the local allocation
			//     range
			// * Non-tunnel mode:
			//   * May not be targeted to an IP in the cluster range
			if err := runProg("iptables", append(
				m.waitArgs,
				"-t", "nat",
				"-A", ciliumPostNatChain,
				"-s", node.GetIPv4AllocRange().String(),
				"!", "-d", egressSnatDstAddrExclusion,
				"!", "-o", "cilium_+",
				"-m", "comment", "--comment", "cilium masquerade non-cluster",
				"-j", "MASQUERADE"), false); err != nil {
				return err
			}

			// The following rules exclude traffic from the remaining rules in this chain.
			// If any of these rules match, none of the remaining rules in this chain
			// are considered.
			// Exclude traffic for other than ifName interface from the masquarade rules.
			// RETURN fro the chain as it is possible that other rules need to be matched.
			if err := runProg("iptables", append(
				m.waitArgs,
				"-t", "nat",
				"-A", ciliumPostNatChain,
				"!", "-o", ifName,
				"-m", "comment", "--comment", "exclude non-"+ifName+" traffic from masquerade",
				"-j", "RETURN"), false); err != nil {
				return err
			}

			// Exclude crypto traffic from the masquarade rules
			// Crypto traffic does not need to hit any other rules in the table,
			// so we can ACCEPT for the nat table.
			if err := runProg("iptables", append(
				m.waitArgs,
				"-t", "nat",
				"-A", ciliumPostNatChain,
				"-m", "mark", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
				"-m", "comment", "--comment", "exclude encrypt from masquerade",
				"-j", "ACCEPT"), false); err != nil {
				return err
			}
			if err := runProg("iptables", append(
				m.waitArgs,
				"-t", "nat",
				"-A", ciliumPostNatChain,
				"-m", "mark", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
				"-m", "comment", "--comment", "exclude decrypt from masquerade",
				"-j", "ACCEPT"), false); err != nil {
				return err
			}

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
				"!", "-s", ingressSnatSrcAddrExclusion,
				"!", "-d", node.GetIPv4AllocRange().String(),
				"-m", "comment", "--comment", "cilium host->cluster masquerade",
				"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()), false); err != nil {
				return err
			}

			// Masquerade all traffic from the host into the ifName
			// interface if the source is 127.0.0.1
			//
			// The following conditions must be met:
			// * Must be targeted for the ifName interface
			// * Must be from 127.0.0.1
			if err := runProg("iptables", append(
				m.waitArgs,
				"-t", "nat",
				"-A", ciliumPostNatChain,
				"-s", "127.0.0.1",
				"-m", "comment", "--comment", "cilium host->cluster from 127.0.0.1 masquerade",
				"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()), false); err != nil {
				return err
			}

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
	}

	if option.Config.EnableIPSec {
		if err := m.addCiliumAcceptXfrmRules(); err != nil {
			return fmt.Errorf("cannot install xfrm rules: %s", err)
		}

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

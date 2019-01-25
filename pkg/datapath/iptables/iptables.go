// Copyright 2016-2018 Authors of Cilium
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
	"reflect"
	"strings"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"

	"github.com/mattn/go-shellwords"
	"github.com/sirupsen/logrus"
)

const (
	tableNat    tableName = "nat"
	tableMangle tableName = "mangle"
	tableRaw    tableName = "raw"
	tableFilter tableName = "filter"
)

var (
	tables = []tableName{tableNat, tableMangle, tableRaw, tableFilter}
)

// custom chain names
const (
	ciliumOutputChain     chainName = "CILIUM_OUTPUT"
	ciliumPostNatChain    chainName = "CILIUM_POST"
	ciliumPostMangleChain chainName = "CILIUM_POST_mangle"
	ciliumForwardChain    chainName = "CILIUM_FORWARD"
)

func runProg(prog string, args []string, quiet bool) error {
	log.Debugf("Executing %s %s", prog, strings.Join(args, " "))
	_, err := exec.WithTimeout(defaults.ExecTimeout, prog, args...).CombinedOutput(log, !quiet)
	if err != nil {
		log.WithError(err).Warningf("Error while executing %s %sv", prog, strings.Join(args, " "))
	}
	return err
}

func getFeedRule(name chainName) []string {
	return []string{"-m", "comment", "--comment", "cilium-feeder: " + string(name), "-j", string(name)}
}

// rule is an iptables rule minus the table and chain name
type rule []string

// Equal returns true if two rules are identical
//
// NOTE: The rule must be described in the same way as `iptables-save` prints it
func (r rule) Equal(o rule) bool {
	return reflect.DeepEqual(r, o)
}

// rules is a list of rules
type rules []rule

type chainName string

// chains is a map of chains with given rules, indexed by chain name
type chains map[chainName]rules

// add adds a rule to a given chain
func (c chains) add(chain chainName, rule rule) {
	if _, ok := c[chain]; !ok {
		c[chain] = rules{}
	}

	c[chain] = append(c[chain], rule)
}

// equalChain returns true if the chain references by name has identical rules
// as the rules provided
func (c chains) equalChain(chain chainName, rules rules) bool {
	if _, ok := c[chain]; !ok {
		return false
	}

	return reflect.DeepEqual(c[chain], rules)
}

type tableName string

//ruleSet is a set of chains with rules indexed by table name
type ruleSet map[tableName]chains

func newRuleSet() ruleSet {
	return ruleSet{}
}

// add adds a rule to a chain in a given table
func (r ruleSet) add(table tableName, chain chainName, rule rule) {
	if _, ok := r[table]; !ok {
		r[table] = chains{}
	}

	r[table].add(chain, rule)
}

// removeChain removes an entire chain from a ruleset
func (r ruleSet) removeChain(table tableName, chain chainName) bool {
	if _, ok := r[table]; ok {
		if _, ok := r[table][chain]; ok {
			delete(r[table], chain)
			if len(r[table]) == 0 {
				delete(r, table)
			}
			return true
		}
	}

	return false
}

// replaceChain replaces a chain with an entire set of rules
func (r ruleSet) replaceChain(table tableName, chain chainName, rules rules) {
	if _, ok := r[table]; !ok {
		r[table] = chains{}
	}

	r[table][chain] = rules
}

// equalChain returns true if the rules for a given chain in a table are
// identical
func (r ruleSet) equalChain(table tableName, chain chainName, rules rules) bool {
	if _, ok := r[table]; !ok {
		return false
	}

	return r[table].equalChain(chain, rules)
}

// diff generates the difference between an old an new rule set and returns all
// chains that were removed and lists all chains that have at least one
// modification. The rules reported in the modified ruleset are *all* rules as
// per new ruleset, not exclusively the changed rules
func (r ruleSet) diff(o ruleSet) (removed ruleSet, modified ruleSet) {
	removed = newRuleSet()
	modified = newRuleSet()

	for table, chains := range r {
		for chain, rules := range chains {
			for _, rule := range rules {
				removed.add(table, chain, rule)
			}
		}
	}

	for table, chains := range o {
		for chain, rules := range chains {
			removed.removeChain(table, chain)
			if !r.equalChain(table, chain, rules) {
				modified.replaceChain(table, chain, rules)
			}
		}
	}

	return
}

// listCiliumRules creates a ruleset of all currently install Cilium rules
func listCiliumRules() (ruleset ruleSet, err error) {
	ruleset = newRuleSet()
	for _, t := range tables {
		ruleset[t], err = listCiliumTableRules(t)
		if err != nil {
			return
		}
	}
	return
}

func listCiliumTableRules(table tableName) (chains, error) {
	c := chains{}

	prog := "iptables"
	args := []string{"-t", string(table), "-S"}

	out, err := exec.WithTimeout(defaults.ExecTimeout, prog, args...).CombinedOutput(log, true)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		rule := scanner.Text()

		// All rules installed by cilium either belong to a chain with
		// the name CILIUM_ or call a chain with the name CILIUM_:
		// -A CILIUM_FORWARD -o cilium_host -m comment --comment "cilium: any->cluster on cilium_host forward accept" -j ACCEPT
		if strings.Contains(rule, "CILIUM_") {
			argsList, err := shellwords.Parse(rule)
			if err != nil {
				return nil, err
			}

			if len(argsList) < 3 {
				continue
			}

			if argsList[0] != "-I" && argsList[0] != "-A" {
				continue
			}

			// ignore the feeder rules
			if strings.Contains(rule, "-j CILIUM_") {
				continue
			}

			c.add(chainName(argsList[1]), argsList[2:])
		}
	}

	return c, nil
}

func removeCustomChain(table tableName, chain chainName) {
	tablePart := []string{}
	if table != tableFilter {
		tablePart = []string{"-t", string(table)}
	}

	if hook, ok := hookMapping[chain]; ok {
		prefix := append(tablePart, []string{"-D", hook}...)
		runProg("iptables", append(prefix, getFeedRule(chain)...), false)
	} else {
		log.WithFields(logrus.Fields{"table": table, "chain": chain}).Error("Unable to map custom chain to hook")
	}

	runProg("iptables", append(tablePart, []string{"-F", string(chain)}...), true)
	runProg("iptables", append(tablePart, []string{"-X", string(chain)}...), true)
}

var hookMapping = map[chainName]string{
	ciliumOutputChain:     "OUTPUT",
	ciliumPostNatChain:    "POSTROUTING",
	ciliumPostMangleChain: "POSTROUTING",
	ciliumForwardChain:    "FORWARD",
}

// ReplaceRules installs iptables rules for Cilium in specific use-cases
// (most specifically, interaction with kube-proxy).
func ReplaceRules(nodeAddressing datapath.NodeAddressing, ifName string) error {
	existingRules, err := listCiliumRules()
	if err != nil {
		return err
	}

	for table, chains := range existingRules {
		for chain, rules := range chains {
			log.WithFields(logrus.Fields{"table": table, "chain": chain}).Debugf("Existing iptables rule: %#v", rules)
		}
	}

	installMode := "-A"
	if option.Config.PrependIptablesChains {
		installMode = "-I"
	}

	newRuleSet := generateRules(nodeAddressing, ifName)
	for table, chains := range newRuleSet {
		for chain, rules := range chains {
			log.WithFields(logrus.Fields{"table": table, "chain": chain}).Debugf("New iptables rule: %#v", rules)
		}
	}

	removed, modified := existingRules.diff(newRuleSet)

	for table, chains := range modified {
		for chain, rules := range chains {
			log.WithFields(logrus.Fields{"table": table, "chain": chain}).Info("Detected changes in chain, re-recreating...")

			removeCustomChain(table, chain)

			tablePart := []string{}
			if table != tableFilter {
				tablePart = []string{"-t", string(table)}
			}

			runProg("iptables", append(tablePart, []string{"-N", string(chain)}...), false)

			for _, rule := range rules {
				prefix := append(tablePart, []string{"-A", string(chain)}...)
				runProg("iptables", append(prefix, rule...), false)
			}

			if hook, ok := hookMapping[chain]; ok {
				prefix := append(tablePart, []string{installMode, hook}...)
				runProg("iptables", append(prefix, getFeedRule(chain)...), false)
			} else {
				log.WithFields(logrus.Fields{"table": table, "chain": chain}).Error("Unable to map custom chain to hook")
			}
		}
	}

	// remove chains that are no longer needed
	for table, chains := range removed {
		for chain := range chains {
			log.WithFields(logrus.Fields{"table": table, "chain": chain}).Info("Removing unused iptables chain")
			removeCustomChain(table, chain)
		}
	}

	return nil
}

// generateRules generates the entire Cilium ruleset
//
// WARNING: All rules specified in the function must be specified in the same
// way as `iptables-save` emits them again to ensure that rule changes can be
// detected properly. To verify this, run the agent in debug mode with the new
// rules applied and then restart the agent again. Check for the message:
// "Detected changes in chain, re-recreating...". If it appears enable
// debugging mode and compare the "Existing iptables rule: [...]" message with
// the "New iptables rule: [...] message to identify what is missing.
//
func generateRules(nodeAddressing datapath.NodeAddressing, ifName string) ruleSet {
	rules := newRuleSet()
	matchFromIPSecEncrypt := fmt.Sprintf("%#x/%#x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
	matchFromIPSecDecrypt := fmt.Sprintf("%#x/%#x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)

	// Clear the Kubernetes masquerading mark bit to skip source PAT
	// performed by kube-proxy for all packets destined for Cilium. Cilium
	// installs a dedicated rule which does the source PAT to the right
	// source IP.
	clearMasqBit := fmt.Sprintf("%#x/%#x", 0, proxy.MagicMarkK8sMasq)
	rules.add(tableMangle, ciliumPostMangleChain, []string{
		"!", "-s", "127.0.0.1/32",
		"-o", ifName,
		"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
		"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
		"-m", "comment", "--comment", "cilium: clear masq bit for pkts to " + ifName,
		"-j", "MARK", "--set-xmark", clearMasqBit})

	// kube-proxy does not change the default policy of the FORWARD chain
	// which means that while packets to services are properly DNAT'ed,
	// they are later dropped in the FORWARD chain. The issue has been
	// resolved in #52569 and will be fixed in k8s >= 1.8. The following is
	// a workaround for earlier Kubernetes versions.
	//
	// Accept all packets in FORWARD chain that are going to ifName.
	// It is safe to ignore the destination IP here as the pre-requisite
	// for a packet being routed to ifName is that a route exists
	// which is only installed for known node IP CIDR ranges.
	rules.add(tableFilter, ciliumForwardChain, []string{
		"-o", ifName,
		"-m", "comment", "--comment", "cilium: any->cluster on " + ifName + " forward accept",
		"-j", "ACCEPT"})

	// Accept all packets in the FORWARD chain that are coming from the
	// ifName interface with a source IP in the local node
	// allocation range.
	rules.add(tableFilter, ciliumForwardChain, []string{
		"-s", nodeAddressing.IPv4().AllocationCIDR().String(),
		"-m", "comment", "--comment", "cilium: cluster->any forward accept",
		"-j", "ACCEPT"})

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
	matchFromProxy := fmt.Sprintf("%#x/%#x", proxy.MagicMarkIsProxy, proxy.MagicMarkProxyMask)
	markAsFromHost := fmt.Sprintf("%#x/%#x", proxy.MagicMarkHost, proxy.MagicMarkHostMask)
	rules.add(tableFilter, ciliumOutputChain, []string{
		"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
		"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
		"-m", "mark", "!", "--mark", matchFromProxy, // Don't match proxy traffic
		"-m", "comment", "--comment", "cilium: host->any mark as from host",
		"-j", "MARK", "--set-xmark", markAsFromHost})

	if option.Config.Masquerade {
		ingressSnatSrcAddrExclusion := node.GetHostMasqueradeIPv4().String() + "/32"
		if option.Config.Tunnel == option.TunnelDisabled {
			ingressSnatSrcAddrExclusion = node.GetIPv4ClusterRange().String()
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
		rules.add(tableNat, ciliumPostNatChain, []string{
			"!", "-s", ingressSnatSrcAddrExclusion,
			"!", "-d", nodeAddressing.IPv4().AllocationCIDR().String(),
			"-o", ifName,
			"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
			"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
			"-m", "comment", "--comment", "cilium host->cluster masquerade",
			"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()})

		// Masquerade all traffic from a local endpoint that is routed
		// back to an endpoint on the same node. This happens if a
		// local endpoint talks to a Kubernetes NodePort or HostPort.
		rules.add(tableNat, ciliumPostNatChain, []string{
			"-s", nodeAddressing.IPv4().AllocationCIDR().String(),
			"-o", ifName,
			"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
			"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
			"-m", "comment", "--comment", "cilium hostport loopback masquerade",
			"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()})

		egressSnatDstAddrExclusion := nodeAddressing.IPv4().AllocationCIDR().String()
		if option.Config.Tunnel == option.TunnelDisabled {
			egressSnatDstAddrExclusion = node.GetIPv4ClusterRange().String()
		}

		// Masquerade all egress traffic leaving the node
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
		rules.add(tableNat, ciliumPostNatChain, []string{
			"-s", nodeAddressing.IPv4().AllocationCIDR().String(),
			"!", "-d", egressSnatDstAddrExclusion,
			"!", "-o", "cilium_+",
			"-m", "comment", "--comment", "cilium masquerade non-cluster",
			"-j", "MASQUERADE"})
	}

	return rules
}

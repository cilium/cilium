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
	"strings"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"

	"github.com/mattn/go-shellwords"
)

const (
	ciliumOutputChain     = "CILIUM_OUTPUT"
	ciliumPostNatChain    = "CILIUM_POST"
	ciliumPostMangleChain = "CILIUM_POST_mangle"
	ciliumForwardChain    = "CILIUM_FORWARD"
	feederDescription     = "cilium-feeder:"
)

type customChain struct {
	name       string
	table      string
	hook       string
	feederArgs []string
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

func (c *customChain) add() error {
	return runProg("iptables", []string{"-t", c.table, "-N", c.name}, false)
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

func removeCiliumRules(table string) {
	prog := "iptables"
	args := []string{"-t", table, "-S"}

	out, err := exec.WithTimeout(defaults.ExecTimeout, prog, args...).CombinedOutput(log, true)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		rule := scanner.Text()
		log.WithField(logfields.Object, logfields.Repr(rule)).Debug("Considering removing iptables rule")

		// All rules installed by cilium either belong to a chain with
		// the name CILIUM_ or call a chain with the name CILIUM_:
		// -A CILIUM_FORWARD -o cilium_host -m comment --comment "cilium: any->cluster on cilium_host forward accept" -j ACCEPT
		// -A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST" -j CILIUM_POST
		if strings.Contains(rule, "CILIUM_") {
			reversedRule, err := reverseRule(rule)
			if err != nil {
				log.WithError(err).WithField(logfields.Object, rule).Warn("Unable to parse iptables rule into slice. Leaving rule behind.")
				continue
			}

			if len(reversedRule) > 0 {
				deleteRule := append([]string{"-t", table}, reversedRule...)
				log.WithField(logfields.Object, logfields.Repr(deleteRule)).Debug("Removing iptables rule")
				err = runProg("iptables", deleteRule, true)
				if err != nil {
					log.WithError(err).WithField(logfields.Object, rule).Warn("Unable to delete Cilium iptables rule")
				}
			}
		}
	}
}

func (c *customChain) remove() {
	runProg("iptables", []string{
		"-t", c.table,
		"-F", c.name}, true)

	runProg("iptables", []string{
		"-t", c.table,
		"-X", c.name}, true)
}

func (c *customChain) installFeeder() error {
	installMode := "-A"
	if option.Config.PrependIptablesChains {
		installMode = "-I"
	}

	for _, feedArgs := range c.feederArgs {
		err := runProg("iptables", append([]string{"-t", c.table, installMode, c.hook}, getFeedRule(c.name, feedArgs)...), true)
		if err != nil {
			return err
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
		name:       ciliumPostMangleChain,
		table:      "mangle",
		hook:       "POSTROUTING",
		feederArgs: []string{""},
	},
	{
		name:       ciliumForwardChain,
		table:      "filter",
		hook:       "FORWARD",
		feederArgs: []string{""},
	},
}

// RemoveRules removes iptables rules installed by Cilium.
func RemoveRules() {
	tables := []string{"nat", "mangle", "raw", "filter"}
	for _, t := range tables {
		removeCiliumRules(t)
	}

	for _, c := range ciliumChains {
		c.remove()
	}
}

// InstallRules installs iptables rules for Cilium in specific use-cases
// (most specifically, interaction with kube-proxy).
func InstallRules() error {
	for _, c := range ciliumChains {
		if err := c.add(); err != nil {
			return fmt.Errorf("cannot add custom chain %s: %s", c.name, err)
		}
	}

	// Clear the Kubernetes masquerading mark bit to skip source PAT
	// performed by kube-proxy for all packets destined for Cilium. Cilium
	// installs a dedicated rule which does the source PAT to the right
	// source IP.
	clearMasqBit := fmt.Sprintf("%#08x/%#08x", 0, proxy.MagicMarkK8sMasq)
	if err := runProg("iptables", []string{
		"-t", "mangle",
		"-A", ciliumPostMangleChain,
		"-o", defaults.HostDevice,
		"!", "-s", "127.0.0.1",
		"-m", "comment", "--comment", "cilium: clear masq bit for pkts to " + defaults.HostDevice,
		"-j", "MARK", "--set-xmark", clearMasqBit}, false); err != nil {
		return err
	}

	// kube-proxy does not change the default policy of the FORWARD chain
	// which means that while packets to services are properly DNAT'ed,
	// they are later dropped in the FORWARD chain. The issue has been
	// resolved in #52569 and will be fixed in k8s >= 1.8. The following is
	// a workaround for earlier Kubernetes versions.
	//
	// Accept all packets in FORWARD chain that are going to defaults.HostDevice.
	// It is safe to ignore the destination IP here as the pre-requisite
	// for a packet being routed to defaults.HostDevice is that a route exists
	// which is only installed for known node IP CIDR ranges.
	if err := runProg("iptables", []string{
		"-A", ciliumForwardChain,
		"-o", defaults.HostDevice,
		"-m", "comment", "--comment", "cilium: any->cluster on " + defaults.HostDevice + " forward accept",
		"-j", "ACCEPT"}, false); err != nil {
		return err
	}

	// Accept all packets in the FORWARD chain that are coming from the
	// defaults.HostDevice interface with a source IP in the local node
	// allocation range.
	if err := runProg("iptables", []string{
		"-A", ciliumForwardChain,
		"-s", node.GetIPv4AllocRange().String(),
		"-m", "comment", "--comment", "cilium: cluster->any forward accept",
		"-j", "ACCEPT"}, false); err != nil {
		return err
	}

	// Mark all packets sourced from processes running on the host with a
	// special marker so that we can differentiate traffic sourced locally
	// vs. traffic from the outside world that was masqueraded to appear
	// like it's from the host.
	//
	// Originally we set this mark only for traffic destined to the
	// defaults.HostDevice device, to ensure that any traffic directly reaching
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
	if err := runProg("iptables", []string{
		"-t", "filter",
		"-A", ciliumOutputChain,
		"-m", "mark", "!", "--mark", matchFromProxy, // Don't match proxy traffic
		"-m", "comment", "--comment", "cilium: host->any mark as from host",
		"-j", "MARK", "--set-xmark", markAsFromHost}, false); err != nil {
		return err
	}

	if option.Config.Masquerade {
		ingressSnatSrcAddrExclusion := node.GetHostMasqueradeIPv4().String()
		if option.Config.Tunnel == option.TunnelDisabled {
			ingressSnatSrcAddrExclusion = node.GetIPv4ClusterRange().String()
		}

		// Masquerade all traffic from the host into the defaults.HostDevice
		// interface if the source is not the internal IP
		//
		// The following conditions must be met:
		// * Must be targeted for the defaults.HostDevice interface
		// * Must be targeted to an IP that is not local
		// * Tunnel mode:
		//   * May not already be originating from the masquerade IP
		// * Non-tunnel mode:
		//   * May not orignate from any IP inside of the cluster range
		if err := runProg("iptables", []string{
			"-t", "nat",
			"-A", ciliumPostNatChain,
			"!", "-s", ingressSnatSrcAddrExclusion,
			"!", "-d", node.GetIPv4AllocRange().String(),
			"-o", defaults.HostDevice,
			"-m", "comment", "--comment", "cilium host->cluster masquerade",
			"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()}, false); err != nil {
			return err
		}

		// Masquerade all traffic from a local endpoint that is routed
		// back to an endpoint on the same node. This happens if a
		// local endpoint talks to a Kubernetes NodePort or HostPort.
		if err := runProg("iptables", []string{
			"-t", "nat",
			"-A", ciliumPostNatChain,
			"-s", node.GetIPv4AllocRange().String(),
			"-o", defaults.HostDevice,
			"-m", "comment", "--comment", "cilium hostport loopback masquerade",
			"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()}, false); err != nil {
			return err
		}

		egressSnatDstAddrExclusion := node.GetIPv4AllocRange().String()
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
		if err := runProg("iptables", []string{
			"-t", "nat",
			"-A", "CILIUM_POST",
			"-s", node.GetIPv4AllocRange().String(),
			"!", "-d", egressSnatDstAddrExclusion,
			"!", "-o", "cilium_+",
			"-m", "comment", "--comment", "cilium masquerade non-cluster",
			"-j", "MASQUERADE"}, false); err != nil {
			return err
		}
	}

	for _, c := range ciliumChains {
		if err := c.installFeeder(); err != nil {
			return fmt.Errorf("cannot install feeder rule %s: %s", c.feederArgs, err)
		}
	}

	return nil
}

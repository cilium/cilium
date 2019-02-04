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
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
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
	ciliumPreMangleChain  = "CILIUM_PRE_mangle"
	ciliumForwardChain    = "CILIUM_FORWARD"
	feederDescription     = "cilium-feeder:"
)

type customChain struct {
	name       string
	table      string
	hook       string
	feederArgs []string
	ipv6       bool
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
	err := runProg("iptables", []string{"-t", c.table, "-N", c.name}, false)
	if err == nil && c.ipv6 == true {
		err = runProg("ip6tables", []string{"-t", c.table, "-N", c.name}, false)
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

func removeCiliumRules(table, prog string) {
	args := []string{"-t", table, "-S"}

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
		if strings.Contains(rule, "CILIUM_") {
			reversedRule, err := reverseRule(rule)
			if err != nil {
				log.WithError(err).WithField(logfields.Object, rule).Warnf("Unable to parse %s rule into slice. Leaving rule behind.", prog)
				continue
			}

			if len(reversedRule) > 0 {
				deleteRule := append([]string{"-t", table}, reversedRule...)
				log.WithField(logfields.Object, logfields.Repr(deleteRule)).Debugf("Removing %s rule", prog)
				err = runProg(prog, deleteRule, true)
				if err != nil {
					log.WithError(err).WithField(logfields.Object, rule).Warnf("Unable to delete Cilium %s rule", prog)
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
	if c.ipv6 == true {
		runProg("ip6tables", []string{
			"-t", c.table,
			"-F", c.name}, true)

		runProg("ip6tables", []string{
			"-t", c.table,
			"-X", c.name}, true)
	}
}

func (c *customChain) installFeeder() error {
	installMode := "-A"
	if option.Config.PrependIptablesChains {
		installMode = "-I"
	}

	for _, feedArgs := range c.feederArgs {
		err := runProg("iptables", append([]string{"-t", c.table, installMode, c.hook}, getFeedRule(c.name, feedArgs)...), true)
		if err == nil && c.ipv6 == true {
			err = runProg("ip6tables", append([]string{"-t", c.table, installMode, c.hook}, getFeedRule(c.name, feedArgs)...), true)
		}

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
		name:       ciliumPreMangleChain,
		table:      "mangle",
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

// RemoveRules removes iptables rules installed by Cilium.
func RemoveRules() {
	tables := []string{"nat", "mangle", "raw", "filter"}
	for _, t := range tables {
		removeCiliumRules(t, "iptables")
		removeCiliumRules(t, "ip6tables")
	}

	for _, c := range ciliumChains {
		c.remove()
	}
}

func installIngressProxyRule(l4proto string, proxyPort uint16) error {
	// Match
	dscp := proxyPort & 0x3F
	ingressDSCPMatch := fmt.Sprintf("%d", dscp)
	// TPROXY params
	ingressProxyMark := fmt.Sprintf("%#08x/%#08x", proxy.MagicMarkIsToProxy, proxy.MagicMarkHostMask)
	ingressProxyPort := fmt.Sprintf("%d", proxyPort)

	err := runProg("iptables", []string{
		"-t", "mangle",
		"-A", ciliumPreMangleChain,
		"-i", defaults.HostDevice,
		"-d", node.GetIPv4AllocRange().String(),
		"-p", l4proto,
		"-m", "dscp", "--dscp", ingressDSCPMatch,
		"-m", "comment", "--comment", "cilium: TPROXY to host ingress proxy on " + defaults.HostDevice,
		"-j", "TPROXY",
		"--tproxy-mark", ingressProxyMark,
		"--on-port", ingressProxyPort}, false)
	if err == nil {
		err = runProg("ip6tables", []string{
			"-t", "mangle",
			"-A", ciliumPreMangleChain,
			"-i", defaults.HostDevice,
			"-d", node.GetIPv6AllocRange().String(),
			"-p", l4proto,
			"-m", "dscp", "--dscp", ingressDSCPMatch,
			"-m", "comment", "--comment", "cilium: TPROXY to host ingress proxy on " + defaults.HostDevice,
			"-j", "TPROXY",
			"--tproxy-mark", ingressProxyMark,
			"--on-port", ingressProxyPort}, false)
	}
	return err
}

func installEgressProxyRule(l4proto string, proxyPort uint16) error {
	// Match
	dscp := int(proxyPort & 0x3F)
	egressMarkMatch := fmt.Sprintf("%#08x/%#08x", proxy.MagicMarkIsToProxy|dscp, proxy.MagicMarkHostMask|0xFF)
	// TPROXY params
	egressProxyMark := fmt.Sprintf("%#08x/%#08x", proxy.MagicMarkIsToProxy, proxy.MagicMarkHostMask|0xFF)
	egressProxyPort := fmt.Sprintf("%d", proxyPort)
	err := runProg("iptables", []string{
		"-t", "mangle",
		"-A", ciliumPreMangleChain,
		"-i", "lxc+",
		"-p", l4proto,
		"-m", "mark", "--mark", egressMarkMatch,
		"-m", "comment", "--comment", "cilium: TPROXY to host egress proxy on lxc+",
		"-j", "TPROXY",
		"--tproxy-mark", egressProxyMark,
		"--on-port", egressProxyPort}, false)
	if err == nil {
		err = runProg("ip6tables", []string{
			"-t", "mangle",
			"-A", ciliumPreMangleChain,
			"-i", "lxc+",
			"-p", l4proto,
			"-m", "mark", "--mark", egressMarkMatch,
			"-m", "comment", "--comment", "cilium: TPROXY to host egress proxy on lxc+",
			"-j", "TPROXY",
			"--tproxy-mark", egressProxyMark,
			"--on-port", egressProxyPort}, false)
	}
	return err
}

func installProxyRules() error {
	for _, v := range proxy.ProxyPorts {
		// Redirect packets to the host proxy via TPROXY, as directed by the Cilium
		// datapath bpf programs via skb marks (egress) or DSCP (ingress).
		if v.Ingress {
			if err := installIngressProxyRule("tcp", v.ProxyPort); err != nil {
				return err
			}
			if err := installIngressProxyRule("udp", v.ProxyPort); err != nil {
				return err
			}
		} else {
			if err := installEgressProxyRule("tcp", v.ProxyPort); err != nil {
				return err
			}
			if err := installEgressProxyRule("udp", v.ProxyPort); err != nil {
				return err
			}
		}
	}
	return nil
}

// InstallRules installs iptables rules for Cilium in specific use-cases
// (most specifically, interaction with kube-proxy).
func InstallRules(ifName string) error {
	for _, c := range ciliumChains {
		if err := c.add(); err != nil {
			return fmt.Errorf("cannot add custom chain %s: %s", c.name, err)
		}
	}

	if err := installProxyRules(); err != nil {
		return fmt.Errorf("cannot add proxy rules: %s", err)
	}

	matchFromIPSecEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
	matchFromIPSecDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)

	// Clear the Kubernetes masquerading mark bit to skip source PAT
	// performed by kube-proxy for all packets destined for Cilium. Cilium
	// installs a dedicated rule which does the source PAT to the right
	// source IP.
	clearMasqBit := fmt.Sprintf("%#08x/%#08x", 0, proxy.MagicMarkK8sMasq)
	if err := runProg("iptables", []string{
		"-t", "mangle",
		"-A", ciliumPostMangleChain,
		"-o", ifName,
		"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
		"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
		"-m", "comment", "--comment", "cilium: clear masq bit for pkts to " + ifName,
		"-j", "MARK", "--set-xmark", clearMasqBit}, false); err != nil {
		return err
	}

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
	if err := runProg("iptables", []string{
		"-A", ciliumForwardChain,
		"-o", ifName,
		"-m", "comment", "--comment", "cilium: any->cluster on " + ifName + " forward accept",
		"-j", "ACCEPT"}, false); err != nil {
		return err
	}

	// Accept all packets in the FORWARD chain that are coming from the
	// ifName interface with a source IP in the local node
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
	if err := runProg("iptables", []string{
		"-t", "filter",
		"-A", ciliumOutputChain,
		"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
		"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
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
		if err := runProg("iptables", []string{
			"-t", "nat",
			"-A", ciliumPostNatChain,
			"!", "-s", ingressSnatSrcAddrExclusion,
			"!", "-d", node.GetIPv4AllocRange().String(),
			"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
			"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
			"-o", ifName,
			"-m", "comment", "--comment", "cilium host->cluster masquerade",
			"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()}, false); err != nil {
			return err
		}

		// Masquerade all traffic from the host into the ifName
		// interface if the source is 127.0.0.1
		//
		// The following conditions must be met:
		// * Must be targeted for the ifName interface
		// * Must be from 127.0.0.1
		if err := runProg("iptables", []string{
			"-t", "nat",
			"-A", ciliumPostNatChain,
			"-s", "127.0.0.1",
			"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
			"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
			"-o", ifName,
			"-m", "comment", "--comment", "cilium host->cluster from 127.0.0.1 masquerade",
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
			"-m", "mark", "!", "--mark", matchFromIPSecDecrypt, // Don't match ipsec traffic
			"-m", "mark", "!", "--mark", matchFromIPSecEncrypt, // Don't match ipsec traffic
			"-m", "mark", "!", "--mark", matchFromProxy, // Don't match proxy traffic
			"-o", ifName,
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

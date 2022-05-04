// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"github.com/mattn/go-shellwords"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

type customChain struct {
	name       string
	table      string
	hook       string
	feederArgs []string
	ipv6       bool // ip6tables chain in addition to iptables chain
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
		ipv6:       true,
	},
}

func (c *customChain) add() error {
	var err error
	if option.Config.EnableIPv4 {
		err = ip4tables.runProg([]string{"-t", c.table, "-N", c.name}, false)
	}
	if err == nil && option.Config.EnableIPv6 && c.ipv6 == true {
		err = ip6tables.runProg([]string{"-t", c.table, "-N", c.name}, false)
	}
	return err
}

func (c *customChain) doRename(prog iptablesInterface, name string, quiet bool) {
	args := []string{"-t", c.table, "-E", c.name, name}
	operation := "rename"
	combinedOutput, err := prog.runProgCombinedOutput(args, true)
	if err != nil && !quiet {
		log.WithError(err).WithField(logfields.Object, args).Warnf("Unable to %s %s chain %s: %s", operation, prog, c.name, string(combinedOutput))
	}
}

func (c *customChain) rename(name string, quiet bool) {
	if option.Config.EnableIPv4 {
		c.doRename(ip4tables, name, quiet)
	}
	if option.Config.EnableIPv6 && c.ipv6 {
		c.doRename(ip6tables, name, quiet)
	}
}

func (c *customChain) remove(quiet bool) {
	doProcess := func(c *customChain, prog iptablesInterface, args []string, operation string, quiet bool) {
		combinedOutput, err := prog.runProgCombinedOutput(args, true)
		if err != nil && !quiet {
			log.WithError(err).WithField(logfields.Object, args).Warnf("Unable to %s %s chain %s: %s", operation, prog.getProg(), c.name, string(combinedOutput))
		}
	}
	doRemove := func(c *customChain, prog iptablesInterface, quiet bool) {
		args := []string{"-t", c.table, "-F", c.name}
		doProcess(c, prog, args, "flush", quiet)
		args = []string{"-t", c.table, "-X", c.name}
		doProcess(c, prog, args, "delete", quiet)
	}
	if option.Config.EnableIPv4 {
		doRemove(c, ip4tables, quiet)
	}
	if option.Config.EnableIPv6 && c.ipv6 {
		doRemove(c, ip6tables, quiet)
	}
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

func (c *customChain) installFeeder() error {
	installMode := "-A"
	if option.Config.PrependIptablesChains {
		installMode = "-I"
	}

	for _, feedArgs := range c.feederArgs {
		if option.Config.EnableIPv4 {
			err := ip4tables.runProg(append([]string{"-t", c.table, installMode, c.hook}, getFeedRule(c.name, feedArgs)...), true)
			if err != nil {
				return err
			}
		}
		if option.Config.EnableIPv6 && c.ipv6 == true {
			err := ip6tables.runProg(append([]string{"-t", c.table, installMode, c.hook}, getFeedRule(c.name, feedArgs)...), true)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

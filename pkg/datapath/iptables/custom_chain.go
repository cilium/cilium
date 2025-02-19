// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"fmt"
	"strings"
)

type customChain struct {
	name  string
	table string
	hook  string
	ipv6  bool // ip6tables chain in addition to iptables chain
}

// ciliumChains is the list of custom iptables chain used by Cilium. Custom
// chains are used to allow for simple replacements of all rules.
//
// WARNING: If you change or remove any of the feeder rules you have to ensure
// that the old feeder rules is also removed on agent start, otherwise,
// flushing and removing the custom chains will fail.
var ciliumChains = []customChain{
	{
		name:  ciliumInputChain,
		table: "filter",
		hook:  "INPUT",
		ipv6:  true,
	},
	{
		name:  ciliumOutputChain,
		table: "filter",
		hook:  "OUTPUT",
		ipv6:  true,
	},
	{
		name:  ciliumOutputRawChain,
		table: "raw",
		hook:  "OUTPUT",
		ipv6:  true,
	},
	{
		name:  ciliumPostNatChain,
		table: "nat",
		hook:  "POSTROUTING",
		ipv6:  true,
	},
	{
		name:  ciliumOutputNatChain,
		table: "nat",
		hook:  "OUTPUT",
	},
	{
		name:  ciliumPreNatChain,
		table: "nat",
		hook:  "PREROUTING",
	},
	{
		name:  ciliumPostMangleChain,
		table: "mangle",
		hook:  "POSTROUTING",
	},
	{
		name:  ciliumPreMangleChain,
		table: "mangle",
		hook:  "PREROUTING",
		ipv6:  true,
	},
	{
		name:  ciliumPreRawChain,
		table: "raw",
		hook:  "PREROUTING",
		ipv6:  true,
	},
	{
		name:  ciliumForwardChain,
		table: "filter",
		hook:  "FORWARD",
		ipv6:  true,
	},
}

func (c *customChain) exists(prog runnable) (bool, error) {
	args := []string{"-t", c.table, "-S", c.name}

	output, err := prog.runProgOutput(args)
	if err != nil {
		if strings.Contains(err.Error(), "No chain/target/match by that name.") {
			return false, nil
		}

		// with iptables-nft >= 1.8.7, when we try to list the rules of a non existing
		// chain, the command will return an error in the format:
		//
		//     chain `$chain' in table `$chain' is incompatible, use 'nft' tool.
		//
		// rather than the usual one:
		//
		//     No chain/target/match by that name.
		if strings.Contains(err.Error(), fmt.Sprintf("chain `%s' in table `%s' is incompatible, use 'nft' tool.", c.name, c.table)) {
			return false, nil
		}
		// with iptables-nft = 1.8.10, when we try to list the rules of a non existing
		// chain, the command will return an error in the format:
		//
		// iptables: Incompatible with this kernel.
		// ip6tables: Incompatible with this kernel.
		//
		// rather than the usual one.
		// This is fixed in 1.8.11. RHEL 9.4 ships however 1.8.10 and is used by all the latest OpenShift versions at
		// the time of writing: 4.16, 4.17 and 4.18
		if strings.Contains(err.Error(), "tables: Incompatible with this kernel.") {
			return false, nil
		}
		return false, fmt.Errorf("unable to list %s chain: %s (%w)", c.name, string(output), err)
	}

	return true, nil
}

func (c *customChain) doAdd(prog runnable) error {
	args := []string{"-t", c.table, "-N", c.name}

	output, err := prog.runProgOutput(args)
	if err != nil {
		return fmt.Errorf("unable to add %s chain: %s (%w)", c.name, string(output), err)
	}

	return nil
}

func (c *customChain) add(ipv4, ipv6 bool) error {
	if ipv4 {
		if err := c.doAdd(ip4tables); err != nil {
			return err
		}
	}
	if ipv6 && c.ipv6 {
		if err := c.doAdd(ip6tables); err != nil {
			return err
		}
	}

	return nil
}

func (c *customChain) doRename(prog runnable, newName string) error {
	if exists, err := c.exists(prog); err != nil {
		return err
	} else if !exists {
		return nil
	}

	args := []string{"-t", c.table, "-E", c.name, newName}

	output, err := prog.runProgOutput(args)
	if err != nil {
		return fmt.Errorf("unable to rename %s chain to %s: %s (%w)", c.name, newName, string(output), err)
	}

	return nil
}

func (c *customChain) rename(ipv4, ipv6 bool, name string) error {
	if ipv4 {
		if err := c.doRename(ip4tables, name); err != nil {
			return err
		}
	}
	if ipv6 && c.ipv6 {
		if err := c.doRename(ip6tables, name); err != nil {
			return nil
		}
	}

	return nil
}

func (c *customChain) doRemove(prog iptablesInterface) error {
	if exists, err := c.exists(prog); err != nil {
		return err
	} else if !exists {
		return nil
	}

	args := []string{"-t", c.table, "-F", c.name}

	output, err := prog.runProgOutput(args)
	if err != nil {
		return fmt.Errorf("unable to flush %s chain: %s (%w)", c.name, string(output), err)
	}

	args = []string{"-t", c.table, "-X", c.name}

	output, err = prog.runProgOutput(args)
	if err != nil {
		return fmt.Errorf("unable to remove %s chain: %s (%w)", c.name, string(output), err)
	}

	return nil
}

func (c *customChain) remove(ipv4, ipv6 bool) error {
	if ipv4 {
		if err := c.doRemove(ip4tables); err != nil {
			return err
		}
	}
	if ipv6 && c.ipv6 {
		if err := c.doRemove(ip6tables); err != nil {
			return err
		}
	}

	return nil
}

func (c *customChain) doInstallFeeder(prog iptablesInterface, prepend bool) error {
	installMode := "-A"
	if prepend {
		installMode = "-I"
	}

	feedRule := []string{"-m", "comment", "--comment", feederDescription + " " + c.name, "-j", c.name}
	args := append([]string{"-t", c.table, installMode, c.hook}, feedRule...)

	output, err := prog.runProgOutput(args)
	if err != nil {
		return fmt.Errorf("unable to install feeder rule for %s chain: %s (%w)", c.name, string(output), err)
	}

	return nil
}

func (c *customChain) installFeeder(ipv4, ipv6, prepend bool) error {
	if ipv4 {
		if err := c.doInstallFeeder(ip4tables, prepend); err != nil {
			return err
		}
	}
	if ipv6 && c.ipv6 {
		if err := c.doInstallFeeder(ip6tables, prepend); err != nil {
			return err
		}
	}
	return nil
}

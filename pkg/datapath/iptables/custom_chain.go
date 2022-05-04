// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"fmt"
	"strings"

	"github.com/mattn/go-shellwords"

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

func (c *customChain) exists(prog iptablesInterface) (bool, error) {
	args := []string{"-t", c.table, "-L", c.name}

	output, err := prog.runProgCombinedOutput(args)
	if err != nil {
		if strings.Contains(string(output), "No chain/target/match by that name.") {
			return false, nil
		}

		return false, fmt.Errorf("unable to list %s chain: %s (%w)", c.name, string(output), err)
	}

	return true, nil
}

func (c *customChain) doAdd(prog iptablesInterface) error {
	args := []string{"-t", c.table, "-N", c.name}

	output, err := prog.runProgCombinedOutput(args)
	if err != nil {
		return fmt.Errorf("unable to add %s chain: %s (%w)", c.name, string(output), err)
	}

	return nil
}

func (c *customChain) add() error {
	if option.Config.EnableIPv4 {
		if err := c.doAdd(ip4tables); err != nil {
			return err
		}
	}
	if option.Config.EnableIPv6 && c.ipv6 == true {
		if err := c.doAdd(ip6tables); err != nil {
			return err
		}
	}

	return nil
}

func (c *customChain) doRename(prog iptablesInterface, newName string) error {
	if exists, err := c.exists(prog); err != nil {
		return err
	} else if !exists {
		return nil
	}

	args := []string{"-t", c.table, "-E", c.name, newName}

	output, err := prog.runProgCombinedOutput(args)
	if err != nil {
		return fmt.Errorf("unable to rename %s chain to %s: %s (%w)", c.name, newName, string(output), err)
	}

	return nil
}

func (c *customChain) rename(name string) error {
	if option.Config.EnableIPv4 {
		if err := c.doRename(ip4tables, name); err != nil {
			return err
		}
	}
	if option.Config.EnableIPv6 && c.ipv6 {
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

	output, err := prog.runProgCombinedOutput(args)
	if err != nil {
		return fmt.Errorf("unable to flush %s chain: %s (%w)", c.name, string(output), err)
	}

	args = []string{"-t", c.table, "-X", c.name}

	output, err = prog.runProgCombinedOutput(args)
	if err != nil {
		return fmt.Errorf("unable to remove %s chain: %s (%w)", c.name, string(output), err)
	}

	return nil
}

func (c *customChain) remove() error {
	if option.Config.EnableIPv4 {
		if err := c.doRemove(ip4tables); err != nil {
			return err
		}
	}
	if option.Config.EnableIPv6 && c.ipv6 {
		if err := c.doRemove(ip6tables); err != nil {
			return err
		}
	}

	return nil
}

func (c *customChain) doInstallFeeder(prog iptablesInterface, feedArgs string) error {
	installMode := "-A"
	if option.Config.PrependIptablesChains {
		installMode = "-I"
	}

	feedRule := []string{"-m", "comment", "--comment", feederDescription + " " + c.name, "-j", c.name}
	if feedArgs != "" {
		argsList, err := shellwords.Parse(feedArgs)
		if err != nil {
			return fmt.Errorf("cannot parse '%s' rule into argument slice: %w", feedArgs, err)
		}

		feedRule = append(argsList, feedRule...)
	}

	args := append([]string{"-t", c.table, installMode, c.hook}, feedRule...)

	output, err := prog.runProgCombinedOutput(args)
	if err != nil {
		return fmt.Errorf("unable to install feeder rule for %s chain: %s (%w)", c.name, string(output), err)
	}

	return nil
}

func (c *customChain) installFeeder() error {
	for _, feedArgs := range c.feederArgs {
		if option.Config.EnableIPv4 {
			if err := c.doInstallFeeder(ip4tables, feedArgs); err != nil {
				return err
			}
		}
		if option.Config.EnableIPv6 && c.ipv6 == true {
			if err := c.doInstallFeeder(ip6tables, feedArgs); err != nil {
				return err
			}
		}
	}

	return nil
}

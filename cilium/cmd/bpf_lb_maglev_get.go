// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package cmd

import (
	"errors"
	"strconv"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/lbmap"

	"github.com/spf13/cobra"
)

var bpfMaglevGetCmd = &cobra.Command{
	Use:     "get <service id>",
	Aliases: []string{"get"},
	Short:   "Get Maglev lookup table for given service by ID",
	PreRun:  requireServiceID,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf lb maglev get")

		svcIDUint64, err := strconv.ParseUint(args[0], 10, 16)
		if err != nil {
			Fatalf("Unable to parse %s: %s", args[0], err)
		}
		svcID := uint16(svcIDUint64)
		key := &lbmap.MaglevOuterKey{RevNatID: svcID}
		key = key.ToNetwork()
		val := &lbmap.MaglevOuterVal{}

		lookupTables := map[string][]string{}
		found := false

		tableSize, err := lbmap.OpenMaglevMaps()
		if err != nil {
			Fatalf("Cannot initialize maglev maps: %s", err)
		}

		for name, m := range lbmap.GetOpenMaglevMaps() {
			if err := m.Lookup(key, val); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					continue
				}
				Fatalf("Unable to retrieve entry from %s with key %v: %s",
					name, key, err)
			}

			found = true
			parseMaglevEntry(key, val, tableSize, lookupTables)
		}

		if !found {
			Fatalf("No entry for %d svc is found", svcID)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(lookupTables); err != nil {
				Fatalf("Unable to generate JSON output: %s", err)
			}
			return
		}

		TablePrinter("SVC ID", "LOOKUP TABLE", lookupTables)
	},
}

func init() {
	bpfMaglevCmd.AddCommand(bpfMaglevGetCmd)
	command.AddJSONOutput(bpfMaglevGetCmd)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/statedb"
)

var StatedbCmd = &cobra.Command{
	Use:   "statedb",
	Short: "Inspect StateDB",
}

var statedbDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump StateDB contents as JSON",
	Run: func(cmd *cobra.Command, args []string) {
		_, err := client.Statedb.GetStatedbDump(nil, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	},
}

var statedbGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get",
	Run: func(cmd *cobra.Command, args []string) {
		table, err := statedb.NewRemoteTable[*tables.Device]("devices", "localhost:8456")
		if err != nil {
			panic(err)
		}

		iter, err := table.Get(context.TODO(), tables.DeviceNameIndex.Query("lo"))
		if err != nil {
			panic(err)
		}

		for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
			fmt.Printf("%+v\n", obj)
		}
	},
}

func init() {
	StatedbCmd.AddCommand(
		statedbDumpCmd,
		statedbGetCmd,
	)
	RootCmd.AddCommand(StatedbCmd)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/liggitt/tabwriter"
	"github.com/spf13/cobra"

	clientPkg "github.com/cilium/cilium/pkg/client"
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

var statedbDevicesWatch bool

var statedbDevicesCmd = &cobra.Command{
	Use:   "devices",
	Short: "Show the contents of devices table",
	Run: func(cmd *cobra.Command, args []string) {
		client, err := statedb.NewClient(clientPkg.DefaultSockPath())
		if err != nil {
			Fatalf("NewClient: %s", err)
		}
		table := statedb.NewRemoteTable[*tables.Device](client, tables.DeviceTableName)

		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', tabwriter.RememberWidths)
		defer w.Flush()

		fmt.Fprintf(w, "Name\tIndex\tSelected\tType\tMTU\tHWAddr\tFlags\tAddresses\n")

		printDev := func(dev *tables.Device) {
			fmt.Fprintf(w, "%s\t%d\t%v\t%s\t%d\t%s\t%s\t",
				dev.Name, dev.Index, dev.Selected,
				dev.Type, dev.MTU, dev.HardwareAddr, dev.Flags)
			addrs := []string{}
			for _, addr := range dev.Addrs {
				addrs = append(addrs, addr.Addr.String())
			}
			fmt.Fprintf(w, "%s\n", strings.Join(addrs, ", "))
		}

		if !statedbDevicesWatch {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			iter, err := table.LowerBound(ctx, tables.DeviceNameIndex.Query(""))
			if err != nil {
				Fatalf("LowerBound: %s", err)
			}
			for dev, _, ok := iter.Next(); ok; dev, _, ok = iter.Next() {
				printDev(dev)
			}
		} else {
			iter, err := table.Watch(context.Background())
			if err != nil {
				Fatalf("Watch: %s", err)
			}
			type update struct {
				dev     *tables.Device
				deleted bool
			}
			updates := make(chan update)
			go func() {
				defer close(updates)
				for dev, deleted, _, ok := iter.Next(); ok; dev, deleted, _, ok = iter.Next() {
					updates <- update{dev, deleted}
				}
			}()

			// Flush every 100 millis for more nicely aligned output.
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					w.Flush()
				case u, ok := <-updates:
					if !ok {
						return
					}
					if u.deleted {
						fmt.Fprintf(w, "%s\t%d\t(deleted)\t_\t_\t_\t_\t\n", u.dev.Name, u.dev.Index)
					} else {
						printDev(u.dev)
					}
				}
			}

		}
	},
}

func init() {
	StatedbCmd.AddCommand(
		statedbDumpCmd,
		statedbDevicesCmd,
	)

	statedbDevicesCmd.Flags().BoolVarP(&statedbDevicesWatch, "watch", "", false, "Watch for changes")

	RootCmd.AddCommand(StatedbCmd)
}

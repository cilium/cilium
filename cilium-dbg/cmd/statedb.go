// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	controlTables "github.com/cilium/cilium/daemon/tables"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
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

func statedbTableCommand[Obj statedb.TableWritable](tableName string) *cobra.Command {
	var watchInterval time.Duration
	cmd := &cobra.Command{
		Use:   tableName,
		Short: fmt.Sprintf("Show contents of table %q", tableName),
		Run: func(cmd *cobra.Command, args []string) {
			table := statedb.NewRemoteTable[Obj](client, tableName)

			w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
			var obj Obj
			fmt.Fprintf(w, "%s\n", strings.Join(obj.TableHeader(), "\t"))
			defer w.Flush()

			revision := statedb.Revision(0)

			for {
				// Query the contents of the table by revision, so that objects
				// that were last modified are shown last.
				iter, errChan := table.LowerBound(context.Background(), statedb.ByRevision[Obj](revision))

				if iter != nil {
					err := statedb.ProcessEach[Obj](
						iter,
						func(obj Obj, rev statedb.Revision) error {
							// Remember the latest revision to query from.
							revision = rev + 1
							_, err := fmt.Fprintf(w, "%s\n", strings.Join(obj.TableRow(), "\t"))
							return err
						})
					w.Flush()

					if err != nil {
						return
					}
				}

				if err := <-errChan; err != nil {
					Fatalf("LowerBound: %s", err)
				}

				if watchInterval == 0 {
					break
				}

				time.Sleep(watchInterval)
			}

		},
	}
	cmd.Flags().DurationVarP(&watchInterval, "watch", "w", time.Duration(0), "Watch for new changes with the given interval (e.g. --watch=100ms)")
	return cmd
}

func init() {
	StatedbCmd.AddCommand(
		statedbDumpCmd,

		statedbTableCommand[*datapathTables.Device]("devices"),
		statedbTableCommand[*datapathTables.Route]("routes"),
		statedbTableCommand[*datapathTables.L2AnnounceEntry]("l2-announce"),
		statedbTableCommand[*datapathTables.BandwidthQDisc](datapathTables.BandwidthQDiscTableName),
		statedbTableCommand[datapathTables.NodeAddress](datapathTables.NodeAddressTableName),
		statedbTableCommand[*datapathTables.Sysctl](datapathTables.SysctlTableName),
		statedbTableCommand[*controlTables.Service](controlTables.ServiceTableName),
		statedbTableCommand[*controlTables.Backend](controlTables.BackendTableName),
	)
	RootCmd.AddCommand(StatedbCmd)
}

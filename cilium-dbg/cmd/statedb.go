// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/liggitt/tabwriter"
	"github.com/spf13/cobra"

	"github.com/cilium/statedb"

	clientPkg "github.com/cilium/cilium/pkg/client"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/health"
	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/maps/nat/stats"
)

var StatedbCmd = &cobra.Command{
	Use:   "statedb",
	Short: "Inspect StateDB",
}

var statedbDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump StateDB contents as JSON",
	Run: func(cmd *cobra.Command, args []string) {
		transport, err := clientPkg.NewTransport("")
		if err != nil {
			Fatalf("NewTransport: %s", err)
		}
		client := http.Client{Transport: transport}
		resp, err := client.Get(statedbURL.JoinPath("dump").String())
		if err != nil {
			Fatalf("Get(dump): %s", err)
		}
		io.Copy(os.Stdout, resp.Body)
		resp.Body.Close()
	},
}

// StateDB HTTP handler is mounted at /statedb by configureAPIServer() in daemon/cmd/cells.go.
var statedbURL, _ = url.Parse("http://localhost/statedb")

func newRemoteTable[Obj any](tableName string) *statedb.RemoteTable[Obj] {
	table := statedb.NewRemoteTable[Obj](statedbURL, tableName)
	transport, err := clientPkg.NewTransport("")
	if err != nil {
		Fatalf("NewTransport: %s", err)
	}
	table.SetTransport(transport)
	return table
}

func newTabWriter(out io.Writer) *tabwriter.Writer {
	const (
		minWidth = 6
		width    = 4
		padding  = 3
		padChar  = ' '
		flags    = tabwriter.RememberWidths
	)
	return tabwriter.NewWriter(out, minWidth, width, padding, padChar, flags)
}

const (
	// The number of lines before the header is reprinted when watching.
	watchReprintHeaderInterval = 100
)

func statedbTableCommand[Obj statedb.TableWritable](tableName string) *cobra.Command {
	var watchInterval time.Duration
	cmd := &cobra.Command{
		Use:   tableName,
		Short: fmt.Sprintf("Show contents of table %q", tableName),
		Run: func(cmd *cobra.Command, args []string) {
			table := newRemoteTable[Obj](tableName)

			w := newTabWriter(os.Stdout)
			var obj Obj
			fmt.Fprintf(w, "# %s\n", strings.Join(obj.TableHeader(), "\t"))
			defer w.Flush()

			revision := statedb.Revision(0)
			numLinesSinceHeader := 0

			for {
				// Query the contents of the table by revision, so that objects
				// that were last modified are shown last.
				iter, errChan := table.LowerBound(context.Background(), statedb.ByRevision[Obj](revision))

				if iter != nil {
					err := statedb.ProcessEach(
						iter,
						func(obj Obj, rev statedb.Revision) error {
							// Remember the latest revision to query from.
							revision = rev + 1
							_, err := fmt.Fprintf(w, "%s\n", strings.Join(obj.TableRow(), "\t"))
							numLinesSinceHeader++
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

				if numLinesSinceHeader > watchReprintHeaderInterval {
					numLinesSinceHeader = 0
					fmt.Fprintf(w, "# %s\n", strings.Join(obj.TableHeader(), "\t"))
					w.Flush()
				}
			}

		},
	}
	cmd.Flags().DurationVarP(&watchInterval, "watch", "w", time.Duration(0), "Watch for new changes with the given interval (e.g. --watch=100ms)")
	return cmd
}

func init() {
	StatedbCmd.AddCommand(
		statedbDumpCmd,

		statedbTableCommand[*tables.Device]("devices"),
		statedbTableCommand[*tables.Route]("routes"),
		statedbTableCommand[*tables.L2AnnounceEntry]("l2-announce"),
		statedbTableCommand[*tables.BandwidthQDisc](tables.BandwidthQDiscTableName),
		statedbTableCommand[tables.NodeAddress](tables.NodeAddressTableName),
		statedbTableCommand[*tables.Sysctl](tables.SysctlTableName),
		statedbTableCommand[types.Status](health.TableName),
		statedbTableCommand[*tables.IPSetEntry](tables.IPSetsTableName),
		statedbTableCommand[bwmap.Edt](bwmap.EdtTableName),
		statedbTableCommand[stats.NatMapStats](stats.TableName),
	)
	RootCmd.AddCommand(StatedbCmd)
}

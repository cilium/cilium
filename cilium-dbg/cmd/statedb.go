// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cilium/statedb"
	"github.com/liggitt/tabwriter"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	clientPkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"

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

var statedbExperimentalCmd = &cobra.Command{
	Use:   "experimental",
	Short: "Experimental",
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

type outputter interface {
	writeHeader()
	writeObject(obj statedb.TableWritable) error
	flush()
}

type tableOutput struct {
	proto               statedb.TableWritable
	w                   *tabwriter.Writer
	numLinesSinceHeader int
}

func (t *tableOutput) writeHeader() {
	fmt.Fprintf(t.w, "# %s\n", strings.Join(t.proto.TableHeader(), "\t"))
}

func (t *tableOutput) writeObject(obj statedb.TableWritable) error {
	_, err := fmt.Fprintf(t.w, "%s\n", strings.Join(obj.TableRow(), "\t"))
	t.numLinesSinceHeader++
	return err
}

func (t *tableOutput) flush() {
	if t.numLinesSinceHeader > watchReprintHeaderInterval {
		t.numLinesSinceHeader = 0
		fmt.Fprintf(t.w, "# %s\n", strings.Join(t.proto.TableHeader(), "\t"))
	}
	t.w.Flush()
}

type jsonOutput struct {
	enc *json.Encoder
}

func (j jsonOutput) writeHeader() {}
func (j jsonOutput) writeObject(obj statedb.TableWritable) error {
	return j.enc.Encode(obj)
}
func (j jsonOutput) flush() {}

type yamlOutput struct {
	enc *yaml.Encoder
}

func (j yamlOutput) writeHeader() {}
func (j yamlOutput) writeObject(obj statedb.TableWritable) error {
	return j.enc.Encode(obj)
}
func (j yamlOutput) flush() {}

func statedbTableCommand[Obj statedb.TableWritable](tableName string) *cobra.Command {
	var (
		watchInterval time.Duration
		outputFormat  string
	)
	cmd := &cobra.Command{
		Use:   tableName,
		Short: fmt.Sprintf("Show contents of table %q", tableName),
		Run: func(cmd *cobra.Command, args []string) {
			table := newRemoteTable[Obj](tableName)

			var proto Obj
			var outputter outputter
			switch outputFormat {
			case "table":
				outputter = &tableOutput{
					proto:               proto,
					w:                   newTabWriter(os.Stdout),
					numLinesSinceHeader: 0,
				}
			case "json":
				outputter = jsonOutput{json.NewEncoder(os.Stdout)}
			case "yaml":
				outputter = yamlOutput{yaml.NewEncoder(os.Stdout)}
			default:
				Fatalf("Unknown output format %q. Choose one of: table, yaml or json.", outputFormat)
			}
			outputter.writeHeader()

			revision := statedb.Revision(0)

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
							return outputter.writeObject(obj)
						})
					outputter.flush()
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
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format, one of: table, json or yaml")
	return cmd
}

func init() {
	statedbExperimentalCmd.AddCommand(
		statedbTableCommand[*experimental.Service](experimental.ServiceTableName),
		statedbTableCommand[*experimental.Frontend](experimental.FrontendTableName),
		statedbTableCommand[*experimental.Backend](experimental.BackendTableName),
	)
	StatedbCmd.AddCommand(
		statedbDumpCmd,
		statedbExperimentalCmd,

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

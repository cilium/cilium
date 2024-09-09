// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
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
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/dynamicconfig"
	"github.com/cilium/cilium/pkg/hive/health"
	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
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

func init() {
	statedbExperimentalCmd.AddCommand(
		statedbTableCommand[*experimental.Service](experimental.ServiceTableName),
		statedbTableCommand[*experimental.Frontend](experimental.FrontendTableName),
		statedbTableCommand[*experimental.Backend](experimental.BackendTableName),
		statedbTableCommand[dynamicconfig.DynamicConfig](dynamicconfig.TableName),
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

func statedbTableCommand[Obj statedb.TableWritable](tableName string) *cobra.Command {
	var (
		watch        bool
		outputFormat string
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
					w:                   newTabWriter(&strikethroughWriter{w: os.Stdout}),
					numLinesSinceHeader: 0,
				}
			case "json":
				if watch {
					Fatalf("--watch not supported with JSON output")
				}
				outputter = jsonOutput{json.NewEncoder(os.Stdout)}
			case "yaml":
				if watch {
					Fatalf("--watch not supported with YAML output")
				}
				outputter = yamlOutput{yaml.NewEncoder(os.Stdout)}
			default:
				Fatalf("Unknown output format %q. Choose one of: table, yaml or json.", outputFormat)
			}
			outputter.writeHeader()
			defer outputter.flush()

			if watch {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				iter, errChan := table.Changes(ctx)
				if iter != nil {
					changes := make(chan statedb.Change[Obj], 1)
					go func() {
						defer close(changes)
						for change := range iter {
							changes <- change
						}
					}()

					ticker := time.NewTicker(100 * time.Millisecond)
					defer ticker.Stop()

					for {
						select {
						case <-ticker.C:
							outputter.flush()
						case change := <-changes:
							err := outputter.writeObject(change.Object, change.Deleted)
							if err != nil {
								cancel()
								for range changes {
								}
								return
							}
						}
					}
				}
				if err := <-errChan; err != nil {
					Fatalf("Changes: %s", err)
				}
			} else {
				iter, errChan := table.LowerBound(context.Background(), statedb.ByRevision[Obj](0))
				if iter != nil {
					for obj := range iter {
						err := outputter.writeObject(obj, false)
						if err != nil {
							return
						}
					}
				}
				if err := <-errChan; err != nil {
					Fatalf("LowerBound: %s", err)
				}
			}

		},
	}
	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "Watch for changes")
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format, one of: table, json or yaml")
	return cmd
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
	writeObject(obj statedb.TableWritable, deleted bool) error
	flush()
}

// strikethroughWriter writes a line of text that is striken through
// if the line contains the magic character at the end before \n.
// This is used to strike through a tab-formatted line without messing
// up with the widths of the cells.
type strikethroughWriter struct {
	buf           []byte
	strikethrough bool
	w             io.Writer
}

var (
	// Magic character to use at the end of the line to denote that this should be
	// striken through.
	// This is to avoid messing up the width calculations in the tab writer, which
	// would happen if ANSI codes were used directly.
	magicStrikethrough        = byte('\xfe')
	magicStrikethroughNewline = []byte("\xfe\n")
)

func stripTrailingWhitespace(buf []byte) []byte {
	idx := bytes.LastIndexFunc(
		buf,
		func(r rune) bool {
			return r != ' ' && r != '\t'
		},
	)
	if idx > 0 {
		return buf[:idx+1]
	}
	return buf
}

func (s *strikethroughWriter) Write(p []byte) (n int, err error) {
	write := func(bs []byte) {
		if err == nil {
			_, e := s.w.Write(bs)
			if e != nil {
				err = e
			}
		}
	}
	for _, c := range p {
		switch c {
		case '\n':
			s.buf = stripTrailingWhitespace(s.buf)

			if s.strikethrough {
				write(beginStrikethrough)
				write(s.buf)
				write(endStrikethrough)
			} else {
				write(s.buf)
			}
			write(newline)

			s.buf = s.buf[:0] // reset len for reuse.
			s.strikethrough = false

			if err != nil {
				return 0, err
			}

		case magicStrikethrough:
			s.strikethrough = true

		default:
			s.buf = append(s.buf, c)
		}
	}
	return len(p), nil
}

var _ io.Writer = &strikethroughWriter{}

type tableOutput struct {
	proto               statedb.TableWritable
	w                   *tabwriter.Writer
	numLinesSinceHeader int
}

func (t *tableOutput) writeHeader() {
	fmt.Fprintf(t.w, "# %s\n", strings.Join(t.proto.TableHeader(), "\t"))
}

var (
	beginStrikethrough = []byte("\033[9m")
	endStrikethrough   = []byte("\033[29m")
	newline            = []byte("\n")
)

func (t *tableOutput) writeObject(obj statedb.TableWritable, deleted bool) error {
	_, err := t.w.Write([]byte(strings.Join(obj.TableRow(), "\t")))
	if deleted {
		t.w.Write(magicStrikethroughNewline)
	} else {
		t.w.Write(newline)
	}

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
func (j jsonOutput) writeObject(obj statedb.TableWritable, deleted bool) error {
	return j.enc.Encode(obj)
}
func (j jsonOutput) flush() {}

type yamlOutput struct {
	enc *yaml.Encoder
}

func (j yamlOutput) writeHeader() {}
func (j yamlOutput) writeObject(obj statedb.TableWritable, deleted bool) error {
	return j.enc.Encode(obj)
}
func (j yamlOutput) flush() {}

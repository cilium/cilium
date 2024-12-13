// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/cilium/statedb"
	"github.com/spf13/cobra"

	clientPkg "github.com/cilium/cilium/pkg/client"
)

var StatedbCmd = &cobra.Command{
	Use:   "statedb",
	Short: "Inspect StateDB (deprecated)",
	Run: func(cmd *cobra.Command, args []string) {
		Fatalf(`This command has been deprecated and will be removed in the next Cilium release.

StateDB tables can now be inspected via the Cilium shell:

$ cilium-dbg shell
cilium> help db
(shows help for 'db' command)

cilium> db
(shows all registered tables)

cilium> db/show health
(shows contents of health table)

$ cilium-dbg shell -- db/show health
(shows contents of health table)

$ cilium-dbg shell -- db/show -format=json health
(shows contents as JSON)
`)
	},
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

func init() {
	StatedbCmd.AddCommand(
		statedbDumpCmd,
	)
	RootCmd.AddCommand(StatedbCmd)
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

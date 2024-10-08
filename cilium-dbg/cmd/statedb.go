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

var (
	statedbWatch  bool
	statedbFormat string
)

var StatedbCmd = &cobra.Command{
	Use:   "statedb",
	Short: "Inspect StateDB",
	RunE: func(cmd *cobra.Command, args []string) error {
		switch {
		case len(args) == 0:
			return shellExchange(os.Stdout, "db tables")
		case statedbWatch:
			return shellExchange(os.Stdout, "db watch %s", args[0])
		default:
			return shellExchange(os.Stdout, "db show -format=%s %s", statedbFormat, args[0])
		}
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

func init() {
	StatedbCmd.Flags().BoolVarP(&statedbWatch, "watch", "w", false, "Watch for changes")
	StatedbCmd.Flags().StringVarP(&statedbFormat, "output", "o", "table", "Output format, one of: table, json or yaml")
	StatedbCmd.AddCommand(
		statedbDumpCmd,
	)
	RootCmd.AddCommand(StatedbCmd)
}

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

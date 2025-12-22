// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"

	"github.com/cilium/hive/shell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/tui"
	"github.com/spf13/cobra"

	clientPkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/hive"
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

var statedbTuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "StateDB TUI",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := hive.DefaultShellConfig
		if err := cfg.Parse(cmd.Flags()); err != nil {
			return err
		}
		run := func(cmd string) (string, error) {
			var buf bytes.Buffer
			err := shell.ShellExchange(cfg, &buf, "%s", cmd)
			return buf.String(), err
		}
		tui.Run(cmd.Context(), run, slog.Default())
		return nil
	},
}

func init() {
	StatedbCmd.AddCommand(statedbTuiCmd)
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

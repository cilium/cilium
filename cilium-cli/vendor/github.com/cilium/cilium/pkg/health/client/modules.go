// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"fmt"
	"io"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// ModulesHealth represent hive modules health API.
type ModulesHealth interface {
	// GetHealth retrieves agent modules health.
	GetHealth(params *daemon.GetHealthParams, opts ...daemon.ClientOption) (*daemon.GetHealthOK, error)
}

// GetAndFormatModulesHealth retrieves modules health and formats output.
func GetAndFormatModulesHealth(w io.Writer, clt ModulesHealth, verbose bool) {
	fmt.Fprintf(w, "Modules Health:")
	resp, err := clt.GetHealth(daemon.NewGetHealthParams())
	if err != nil {
		fmt.Fprintf(w, "\t%s\n", err)
		return
	}
	if resp.Payload == nil {
		fmt.Fprintf(w, "\tno health payload detected\n")
		return
	}
	if verbose {
		fmt.Fprintf(w, "\n  Module\tStatus\tMessage\tLast Updated\n")
		for _, m := range resp.Payload.Modules {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%12s\n", m.ModuleID, m.Level, m.Message, m.LastUpdated)
		}
		return
	}
	tally := make(map[cell.Level]int, 4)
	for _, m := range resp.Payload.Modules {
		tally[cell.Level(m.Level)] += 1
	}
	fmt.Fprintf(w, "\t%s(%d) %s(%d) %s(%d) %s(%d)\n",
		cell.StatusStopped,
		tally[cell.StatusStopped],
		cell.StatusDegraded,
		tally[cell.StatusDegraded],
		cell.StatusOK,
		tally[cell.StatusOK],
		cell.StatusUnknown,
		tally[cell.StatusUnknown],
	)
}

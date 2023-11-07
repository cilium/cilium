// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"encoding/json"
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
		fmt.Fprintln(w)
		for _, m := range resp.Payload.Modules {
			n := &cell.StatusNode{}
			if err := json.Unmarshal([]byte(m.Message), n); err != nil {
				panic(err)
			}
			if m.Level == string(cell.StatusUnknown) {
				continue
			}
			fmt.Fprintf(w, "%s", n.StringIndent(2))
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

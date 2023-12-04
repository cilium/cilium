// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	noPod    = "(/)"
	rootNode = "agent"
	noErr    = "<nil>"
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
		r := newRoot(rootNode)
		sort.Slice(resp.Payload.Modules, func(i, j int) bool {
			return resp.Payload.Modules[i].ModuleID < resp.Payload.Modules[j].ModuleID
		})
		for _, m := range resp.Payload.Modules {
			if m.Level == string(cell.StatusUnknown) {
				continue
			}
			if err := buildTree(r, m.Message); err != nil {
				fmt.Fprintf(w, "Modules Health rendering failed: %s\n", err)
			}
		}
		fmt.Fprintln(w, "\n"+r.String())
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

func buildTree(n *node, raw string) error {
	var sn cell.StatusNode
	if err := json.Unmarshal([]byte(raw), &sn); err != nil {
		return err
	}
	build(n, &sn)
	return nil
}

func ensurePath(n *node, pp []string) *node {
	current := n
	for _, p := range pp {
		if v := current.find(p); v != nil {
			current = v
			continue
		}
		current = current.addBranch(strings.Replace(p, noPod, "", 1))
	}

	return current
}

func build(n *node, sn *cell.StatusNode) {
	meta := fmt.Sprintf("[%s] %s", strings.ToUpper(string(sn.LastLevel)), sn.Message)
	if sn.Error != "" {
		meta += " -- " + sn.Error
	}
	meta += fmt.Sprintf(" (%s, x%d)", ToAgeHuman(sn.UpdateTimestamp), sn.Count)
	pp := strings.Split(sn.Name, ".")
	current := ensurePath(n, pp)
	if len(sn.SubStatuses) == 0 {
		current.meta = meta
		return
	}
	for _, s := range sn.SubStatuses {
		build(current, s)
	}
}

// ToAgeHuman converts time to duration.
func ToAgeHuman(t time.Time) string {
	if t.IsZero() {
		return "n/a"
	}

	return duration.HumanDuration(time.Since(t))
}

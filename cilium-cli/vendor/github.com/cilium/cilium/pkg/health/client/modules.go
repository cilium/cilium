// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/pkg/hive/health/types"
)

const (
	noPod    = "(/)"
	rootNode = ""
	noErr    = "<nil>"
)

// GetAndFormatModulesHealth retrieves modules health and formats output.
//
// Deprecated: Following #30925 we will move to either a separate cilium-dbg command or
// use health statedb dump data to render status reports externally.
// Following this we should remove this output as part of status in version v1.17.
func GetAndFormatModulesHealth(w io.Writer, ss []types.Status, verbose bool) {
	// Although status' is received from the statedb remote table according to
	// the order in which it's queried (in our case, by primary index identifier).
	// We sort this to ensure order stability regardless.
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].ID.String() < ss[j].ID.String()
	})
	fmt.Fprintf(w, "Modules Health:")
	if verbose {
		r := newRoot(rootNode)
		for _, s := range ss {
			stack := strings.Split(s.ID.String(), ".")
			upsertTree(r, &s, stack)
		}
		r = r.nodes[0]
		r.parent = nil
		body := strings.ReplaceAll(r.String(), "\n", "\n		")
		fmt.Fprintln(w, "\n\t\t"+body)
		return
	}
	tally := make(map[types.Level]int, 4)
	for _, s := range ss {
		tally[types.Level(s.Level)] += 1
	}
	fmt.Fprintf(w, "\t%s(%d) %s(%d) %s(%d)\n",
		types.LevelStopped,
		tally[types.LevelStopped],
		types.LevelDegraded,
		tally[types.LevelDegraded],
		types.LevelOK,
		tally[types.LevelOK],
	)
}

type TreeView struct {
	root *node
}

func NewTreeView() *TreeView {
	return &TreeView{
		root: newRoot("agent"),
	}
}

func (t *TreeView) Render() {
	fmt.Fprintln(os.Stdout, "\n"+t.root.String())
}

func (t *TreeView) UpsertStatus(ss []types.Status) {
	for _, s := range ss {
		upsertTree(t.root, &s, strings.Split(s.ID.String(), "."))
	}
}

func Render(ss []types.Status) {
	n := newRoot("agent")
	for _, s := range ss {
		upsertTree(n, &s, strings.Split(s.ID.String(), "."))
	}
	body := strings.ReplaceAll(n.String(), "\n", "\n		")
	fmt.Fprintln(os.Stdout, "\n\t\t"+body)
}

// upsertTree inserts a health report, using a stack of path tokens into
// a tree used for displaying health data.
//
// Because there is no longer a distinction between reporter leaves and parent nodes
// (i.e. parents of subtrees can have their own health status) we modify the tree to
// move all such "parent" reports down to a immediate child, such that in our output
// all health reports appear as leaves.

// upsertTree inserts a health report, using a stack of path tokens into
// a tree used for displaying health data.
//
// Because there is no longer a distinction between reporter leaves and parent nodes
// (i.e. parents of subtrees can have their own health status) we modify the tree to
// move all such "parent" reports down to a immediate child, such that in our output
// all health reports appear as leaves.
func upsertTree(r *node, report *types.Status, stack []string) {
	if len(stack) == 1 {
		name := stack[0]
		meta := fmt.Sprintf("[%s] %s", strings.ToUpper(string(report.Level)), report.Message)
		meta += fmt.Sprintf(" (%s, x%d)", ToAgeHuman(report.Updated), report.Count)
		for _, c := range r.nodes {
			if c.val == name {
				c.meta = meta
				c.report = report
				return
			}
		}
		r.addNodeWithMeta(name, meta, report)
		return
	}
	pop := stack[0]
	stack = stack[1:]
	for _, c := range r.nodes {
		if c.val == pop {
			// In this case, if the node was a leaf, it may contain a status.
			// Because parent nodes can now also have health status reports we
			// fix this up by moving the report to a leaf node, thus maintaining
			// the condition that only leaves have reporters.
			if c.report != nil {
				// Move former parent nodes health report to child leaf.
				upsertTree(c, c.report, []string{"[reporter]"})
				c.report = nil
				c.meta = ""
			}
			upsertTree(c, report, stack)
			return
		}
	}
	// Add parent node.
	n := r.addNode(pop, nil)
	upsertTree(n, report, stack)
}

// ToAgeHuman converts time to duration.
func ToAgeHuman(t time.Time) string {
	if t.IsZero() {
		return "n/a"
	}

	return duration.HumanDuration(time.Since(t))
}

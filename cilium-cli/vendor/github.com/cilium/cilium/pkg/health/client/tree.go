// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	indentSize              = 3
	leafMaxWidth            = 40
	link         decoration = "│"
	mid          decoration = "├──"
	end          decoration = "└──"
)

type decoration string

func newRoot(r string) *node {
	return &node{val: r}
}

type node struct {
	val, meta string
	parent    *node
	nodes     []*node
}

func (n *node) addNode(v string) *node {
	return n.addNodeWithMeta(v, "")
}

func (n *node) addNodeWithMeta(v, m string) *node {
	node := node{
		parent: n,
		val:    v,
		meta:   m,
	}
	n.nodes = append(n.nodes, &node)

	return &node
}

func (n *node) addBranch(v string) *node {
	return n.addBranchWithMeta(v, "")
}

func (n *node) addBranchWithMeta(v, m string) *node {
	b := node{
		parent: n,
		meta:   m,
		val:    v,
	}
	n.nodes = append(n.nodes, &b)

	return &b
}

func (n *node) find(val string) *node {
	if n.val == val {
		return n
	}
	for _, node := range n.nodes {
		if node.val == val {
			return node
		}
		if v := node.find(val); v != nil {
			return v
		}
	}

	return nil
}

func (n *node) asBytes() []byte {
	var (
		w           = new(bytes.Buffer)
		levelsEnded []int
		max         = computeMaxLevel(0, n)
	)
	if n.parent == nil {
		w.WriteString(n.val)
		if n.meta != "" {
			w.WriteString(" " + n.meta)
		}
		fmt.Fprintln(w)
	} else {
		edge := mid
		if len(n.nodes) == 0 {
			edge = end
			levelsEnded = append(levelsEnded, 0)
		}
		dumpVals(w, 0, max, levelsEnded, edge, n)
	}
	if len(n.nodes) > 0 {
		dumpNodes(w, 0, max, levelsEnded, n.nodes)
	}

	return w.Bytes()
}

func (n *node) String() string {
	return string(n.asBytes())
}

func (n *node) lastNode() *node {
	c := len(n.nodes)
	if c == 0 {
		return nil
	}

	return n.nodes[c-1]
}

func computeMaxLevel(level int, n *node) int {
	if n == nil || len(n.nodes) == 0 {
		return level
	}
	var max int
	for _, n := range n.nodes {
		m := computeMaxLevel(level+1, n)
		if m > max {
			max = m
		}
	}

	return max
}

func dumpNodes(w io.Writer, level, maxLevel int, levelsEnded []int, nodes []*node) {
	for i, node := range nodes {
		edge := mid
		if i == len(nodes)-1 {
			levelsEnded = append(levelsEnded, level)
			edge = end
		}
		dumpVals(w, level, maxLevel, levelsEnded, edge, node)
		if len(node.nodes) > 0 {
			dumpNodes(w, level+1, maxLevel, levelsEnded, node.nodes)
		}
	}
}

func dumpVals(w io.Writer, level, maxLevel int, levelsEnded []int, edge decoration, node *node) {
	for i := 0; i < level; i++ {
		if isEnded(levelsEnded, i) {
			fmt.Fprint(w, strings.Repeat(" ", indentSize+1))
			continue
		}
		fmt.Fprintf(w, "%s%s", link, strings.Repeat(" ", indentSize))
	}

	val := dumpVal(level, node)
	if node.meta != "" {
		c := maxLevel - level
		if c < 0 {
			c = 0
		}
		fmt.Fprintf(w, "%s %-"+strconv.Itoa(leafMaxWidth+c*2)+"s%s%s\n", edge, val, strings.Repeat("  ", c), node.meta)
		return
	}
	fmt.Fprintf(w, "%s %s\n", edge, val)
}

func isEnded(levelsEnded []int, level int) bool {
	for _, l := range levelsEnded {
		if l == level {
			return true
		}
	}

	return false
}

func dumpVal(level int, node *node) string {
	lines := strings.Split(node.val, "\n")
	if len(lines) < 2 {
		return node.val
	}

	pad := indent(level, node)
	for i := 1; i < len(lines); i++ {
		lines[i] = fmt.Sprintf("%s%s", pad, lines[i])
	}

	return strings.Join(lines, "\n")
}

func indent(level int, node *node) string {
	links := make([]string, level+1)
	for node.parent != nil {
		if isLast(node) {
			links[level] = strings.Repeat(" ", indentSize+1)
		} else {
			links[level] = fmt.Sprintf("%s%s", link, strings.Repeat(" ", indentSize))
		}
		level--
		node = node.parent
	}

	return strings.Join(links, "")
}

func isLast(n *node) bool {
	return n == n.parent.lastNode()
}

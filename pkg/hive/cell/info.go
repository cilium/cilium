// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"io"
	"strings"
)

// indentBy is the number of spaces nested elements should be indented by
const indentBy = 4

// Info provides a simple way of printing cells hierarchically in
// textual form.
type Info interface {
	Print(indent int, w io.Writer)
}

type InfoLeaf string

func (l InfoLeaf) Print(indent int, w io.Writer) {
	fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", indent), l)
}

type InfoBreak struct{}

func (l InfoBreak) Print(indent int, w io.Writer) {
	fmt.Fprintln(w)
}

type InfoNode struct {
	// Header line. If missing, no header printed and children
	// not indented.
	header string

	children []Info
}

func NewInfoNode(header string) *InfoNode {
	return &InfoNode{header: header}
}

func (n *InfoNode) Add(child Info) {
	n.children = append(n.children, child)
}

func (n *InfoNode) AddBreak() {
	n.Add(InfoBreak{})
}

func (n *InfoNode) AddLeaf(format string, args ...any) {
	n.Add(InfoLeaf(fmt.Sprintf(format, args...)))
}

func (n *InfoNode) Print(indent int, w io.Writer) {
	if n.header != "" {
		fmt.Fprintf(w, "%s%s:\n", strings.Repeat(" ", indent), n.header)
		indent += indentBy
	}

	for _, child := range n.children {
		child.Print(indent, w)
	}
}

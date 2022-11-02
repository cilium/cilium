// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"io"
	"strings"

	"github.com/davecgh/go-spew/spew"
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

type InfoStruct struct {
	value any
}

func (n *InfoStruct) Print(indent int, w io.Writer) {
	scs := spew.ConfigState{Indent: strings.Repeat(" ", indentBy), SortKeys: true}
	indentString := strings.Repeat(" ", indent)
	for i, line := range strings.Split(scs.Sdump(n.value), "\n") {
		if i == 0 {
			fmt.Fprintf(w, "%s⚙️ %s\n", indentString, line)
		} else {
			fmt.Fprintf(w, "%s%s\n", indentString, line)
		}
	}
}

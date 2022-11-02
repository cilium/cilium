// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/davecgh/go-spew/spew"
)

const (
	// indentBy is the number of spaces nested elements should be indented by
	indentBy = 4

	// maxLineLength is the maximum line length after which the InfoLeaf line
	// wraps.
	maxLineLength = 120
)

// Info provides a simple way of printing cells hierarchically in
// textual form.
type Info interface {
	Print(indent int, w io.Writer)
}

type InfoLeaf string

func (l InfoLeaf) Print(indent int, w io.Writer) {
	buf := bufio.NewWriter(w)
	currentLineLength := indent
	indentString := strings.Repeat(" ", indent)
	buf.WriteString(indentString)
	wrapped := false
	for _, f := range strings.Fields(string(l)) {
		buf.WriteString(f)
		buf.WriteByte(' ')
		currentLineLength += len(f)

		if currentLineLength >= maxLineLength {
			buf.WriteByte('\n')
			if !wrapped {
				// Increase the indent for the wrapped lines so it's clear we
				// wrapped.
				wrapped = true
				indent += 2
				indentString = strings.Repeat(" ", indent)
			}
			buf.WriteString(indentString)
			currentLineLength = indent
		}
	}
	buf.WriteByte('\n')
	buf.Flush()
}

type InfoNode struct {
	// Header line. If missing, no header printed and children
	// not indented.
	header    string
	condensed bool

	children []Info
}

func NewInfoNode(header string) *InfoNode {
	return &InfoNode{header: header}
}

func (n *InfoNode) Condensed() *InfoNode {
	n.condensed = true
	return n
}

func (n *InfoNode) Add(child Info) {
	n.children = append(n.children, child)
}

func (n *InfoNode) AddLeaf(format string, args ...any) {
	n.Add(InfoLeaf(fmt.Sprintf(format, args...)))
}

func (n *InfoNode) Print(indent int, w io.Writer) {
	if n.header != "" {
		fmt.Fprintf(w, "%s%s:\n", strings.Repeat(" ", indent), n.header)
		indent += indentBy
	}

	for i, child := range n.children {
		child.Print(indent, w)
		if !n.condensed && i != len(n.children)-1 {
			w.Write([]byte{'\n'})
		}
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

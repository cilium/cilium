// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	"fmt"
	"io"
	"strings"
)

// TableBuilder is an utility for formatting data as tables.
type TableBuilder struct {
	tableName   string
	columnNames []string
	rows        [][]string
}

func NewEmptyTable(name string, columnNames ...string) *TableBuilder {
	return &TableBuilder{name, columnNames, nil}
}

func (tw *TableBuilder) Write(w io.Writer) {
	// Compute the width of each column. Either length of column name, or
	// the length of widest value in that column.
	colWidths := make([]int, len(tw.columnNames))
	for i, hdr := range tw.columnNames {
		colWidths[i] = len(hdr)
	}
	for _, row := range tw.rows {
		for j, col := range row {
			if len(col) > colWidths[j] {
				colWidths[j] = len(col)
			}
		}
	}

	// Create the divider between the header and rows
	headingDiv := "|"
	for i := range colWidths {
		headingDiv += strings.Repeat("-", colWidths[i]+2)
		if i != len(colWidths)-1 {
			headingDiv += "+"
		}
	}
	headingDiv += "\n"

	// Print out the table name and columnNames
	fmt.Fprintf(w, " - %s %s\n", tw.tableName, strings.Repeat("-", len(headingDiv)-len(tw.tableName)-5))
	w.Write([]byte("| "))
	for i, hdr := range tw.columnNames[:len(tw.columnNames)-1] {
		fmt.Fprintf(w, "%[2]*[1]s | ", hdr, colWidths[i])
	}
	fmt.Fprintf(w, "%[2]*[1]s |\n",
		tw.columnNames[len(tw.columnNames)-1],
		colWidths[len(tw.columnNames)-1])
	w.Write([]byte(headingDiv))

	for _, row := range tw.rows {
		w.Write([]byte{'|'})
		col := 0
		for ; col < len(row); col++ {
			fmt.Fprintf(w, " %*s |", colWidths[col], row[col])
		}
		for ; col < len(colWidths); col++ {
			fmt.Fprintf(w, " %*s |", colWidths[col], "")
		}
		w.Write([]byte{'\n'})
	}

	fmt.Fprintf(w, " %s\n\n", strings.Repeat("-", len(headingDiv)-2))
}

func (tw *TableBuilder) AddRow(fields ...string) {
	tw.rows = append(tw.rows, fields)
}

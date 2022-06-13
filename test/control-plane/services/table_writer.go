// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package services

import (
	"fmt"
	"io"
	"strings"
)

// tableWriter is an utility for formatting data as tables.
type tableWriter struct {
	io.Writer
	tableName   string
	columnNames []string
	rows        [][]string
}

func newTableWriter(w io.Writer, name string, columnNames ...string) *tableWriter {
	return &tableWriter{w, name, columnNames, nil}
}

func (tw *tableWriter) Flush() {
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
	fmt.Fprintf(tw, " - %s %s\n", tw.tableName, strings.Repeat("-", len(headingDiv)-len(tw.tableName)-5))
	tw.Write([]byte("| "))
	for i, hdr := range tw.columnNames[:len(tw.columnNames)-1] {
		fmt.Fprintf(tw, "%[2]*[1]s | ", hdr, colWidths[i])
	}
	fmt.Fprintf(tw, "%[2]*[1]s |\n",
		tw.columnNames[len(tw.columnNames)-1],
		colWidths[len(tw.columnNames)-1])
	tw.Write([]byte(headingDiv))

	for _, row := range tw.rows {
		tw.Write([]byte{'|'})
		col := 0
		for ; col < len(row); col++ {
			fmt.Fprintf(tw, " %*s |", colWidths[col], row[col])
		}
		for ; col < len(colWidths); col++ {
			fmt.Fprintf(tw, " %*s |", colWidths[col], "")
		}
		tw.Write([]byte{'\n'})
	}

	fmt.Fprintf(tw, " %s\n\n", strings.Repeat("-", len(headingDiv)-2))

	tw.tableName = "???"
	tw.rows = nil
	tw.columnNames = nil
}

func (tw *tableWriter) AddRow(fields ...string) {
	tw.rows = append(tw.rows, fields)
}

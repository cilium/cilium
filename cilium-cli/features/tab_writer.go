// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"fmt"
	"io"
	"text/tabwriter"
)

type tabWriter struct {
	tb *tabwriter.Writer
}

func newTabWriter(w io.Writer) statusPrinter {
	return &tabWriter{
		tb: tabwriter.NewWriter(w, 0, 0, 2, ' ', 0),
	}
}

func (t *tabWriter) printHeader(nodesSorted []string) error {
	fmt.Fprintf(t.tb, "Uniform\tName\tLabels\t")
	for _, node := range nodesSorted {
		fmt.Fprintf(t.tb, "%s\t", node)
	}
	fmt.Fprintf(t.tb, "\n")
	return nil
}

func (t *tabWriter) printNode(metricName, labels string, isBinary bool, values map[float64]struct{}, key string, nodesSorted []string, metricsPerNode map[string]map[string]float64) {
	// Determine if "Yes" should be placed in "Uniform" column
	// if len(values) <= 1 then it means that all nodes have a value of
	// either 0 or 1.
	if isBinary {
		if len(values) <= 1 {
			fmt.Fprintf(t.tb, "Yes\t")
		} else {
			fmt.Fprintf(t.tb, "No\t")
		}
	} else {
		fmt.Fprintf(t.tb, " \t")
	}

	fmt.Fprintf(t.tb, "%s\t%s\t", metricName, labels)
	for _, node := range nodesSorted {
		value := metricsPerNode[key][node]
		fmt.Fprintf(t.tb, "%.0f\t", value)
	}
	fmt.Fprintln(t.tb)
}

func (t *tabWriter) end() error {
	return t.tb.Flush()
}

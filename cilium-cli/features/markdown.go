// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"fmt"
	"io"
	"strings"
)

type markdownWriter struct {
	builder *strings.Builder
	writer  io.Writer
}

func newMarkdownWriter(w io.Writer) statusPrinter {
	return &markdownWriter{
		builder: &strings.Builder{},
		writer:  w,
	}
}

func (mw *markdownWriter) printHeader(nodesSorted []string) error {
	mw.builder.WriteString("| Uniform | Name | Labels |")
	for _, node := range nodesSorted {
		mw.builder.WriteString(fmt.Sprintf(" %s |", node))
	}
	mw.builder.WriteString("\n|-|-|")
	for range nodesSorted {
		mw.builder.WriteString("-|")
	}
	mw.builder.WriteString("-|\n")
	return nil
}

func (mw *markdownWriter) printNode(metricName, labels string, isBinary bool, values map[float64]struct{}, key string, nodesSorted []string, metricsPerNode map[string]map[string]float64) {
	if isBinary {
		if len(values) <= 1 {
			mw.builder.WriteString("| :heavy_check_mark: ")
		} else {
			mw.builder.WriteString("| :warning: ")
		}
	} else {
		mw.builder.WriteString("| ")
	}

	mw.builder.WriteString(fmt.Sprintf("| %s | %s |", metricName, labels))

	for _, node := range nodesSorted {
		value := metricsPerNode[key][node]
		mw.builder.WriteString(fmt.Sprintf(" %.0f |", value))
	}
	mw.builder.WriteString(fmt.Sprintln())
}

func (mw *markdownWriter) end() error {
	_, err := fmt.Fprint(mw.writer, mw.builder.String())
	return err
}

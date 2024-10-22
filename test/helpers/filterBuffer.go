// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"bytes"
	"strings"
)

// FilterBuffer structs that extends buffer methods
type FilterBuffer struct {
	*bytes.Buffer
}

// ByLines returns buf string plit by the newline characters
func (buf *FilterBuffer) ByLines() []string {
	out := buf.String()
	sep := "\n"
	if strings.Contains(out, "\r\n") {
		sep = "\r\n"
	}
	out = strings.TrimRight(out, sep)
	return strings.Split(out, sep)
}

// KVOutput returns a map of the buff string split based on
// the separator '='.
// For example, the following strings would be split as follows:
//
//	a=1
//	b=2
//	c=3
func (buf *FilterBuffer) KVOutput() map[string]string {
	result := make(map[string]string)
	for _, line := range buf.ByLines() {
		vals := strings.Split(line, "=")
		if len(vals) == 2 {
			result[vals[0]] = vals[1]
		}
	}
	return result
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package printer

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTerminalEscaperWriter(t *testing.T) {
	colorer := newColorer("always")
	allowedSequences := colorer.sequences()
	builder := newTerminalEscaperBuilder(allowedSequences)

	testCases := []struct {
		name   string
		format string
		args   []any
		want   string
	}{
		{name: "control", args: []any{"\x1b"}, want: "^["},
		{name: "control", args: []any{"\033"}, want: "^["},
		{name: "carriage return", args: []any{"\r"}, want: "\\r"},
		{name: "both", args: []any{"\x1b \r"}, want: "^[ \\r"},
		{name: "formatted args", format: "%d%s%d%s%d", args: []any{1, "\x1b", 3, "\r", 5}, want: "1^[3\\r5"},
		{name: "formatted args split sequence", format: "%s%s", args: []any{"\\", "x1b"}, want: "\\x1b"},
		{name: "formatted args split sequence", format: "%s%s", args: []any{"\\", "033"}, want: "\\033"},
		{
			name: "allowed colors",
			args: []any{
				colorer.red.Sprint("red"),
				colorer.green.Sprint("green"),
				colorer.blue.Sprint("blue"),
				colorer.cyan.Sprint("cyan"),
				colorer.magenta.Sprint("magenta"),
				colorer.yellow.Sprint("yellow"),
			},
			want: "\x1b[31mred\x1b[0m\x1b[32mgreen\x1b[0m\x1b[34mblue\x1b[0m\x1b[36mcyan\x1b[0m\x1b[35mmagenta\x1b[0m\x1b[33myellow\x1b[0m",
		},
	}

	for idx, tc := range testCases {
		t.Run(fmt.Sprintf("%d.%s", idx, tc.name), func(t *testing.T) {
			var buf bytes.Buffer
			tew := builder.NewWriter(&buf)
			if tc.format != "" {
				tew.printf(tc.format, tc.args...)
			} else {
				tew.print(tc.args...)
			}
			got := buf.String()
			assert.Equal(t, tc.want, got)
		})
	}
}

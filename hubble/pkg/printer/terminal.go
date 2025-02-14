// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package printer

import (
	"fmt"
	"io"
	"strings"
)

type terminalEscaperBuilder struct {
	replacer *strings.Replacer
}

// newTerminalEscaperBuilder creates a new terminalEscaperBuilder that allows a subset of control
// sequences, such as a reserved set of colors and their reset sequences.
func newTerminalEscaperBuilder(allowed []string) *terminalEscaperBuilder {
	var oldnew []string
	for _, a := range allowed {
		oldnew = append(oldnew, a, a)
	}
	oldnew = append(oldnew, "\x1b", "^[", "\r", "\\r")
	return &terminalEscaperBuilder{replacer: strings.NewReplacer(oldnew...)}
}

func (teb *terminalEscaperBuilder) NewWriter(w io.Writer) *terminalEscaperWriter {
	return &terminalEscaperWriter{w: w, replacer: teb.replacer}
}

// terminalEscaperWriter replaces ANSI escape sequences and other terminal special
// characters to avoid terminal escape character attacks. It stops on the first error
// encountered and stores its value. The caller is responsible for checking Err()
// when done writing.
type terminalEscaperWriter struct {
	w        io.Writer
	replacer *strings.Replacer
	err      error
}

func (tew *terminalEscaperWriter) print(a ...interface{}) {
	if tew.err != nil {
		return
	}
	_, tew.err = tew.replacer.WriteString(tew.w, fmt.Sprint(a...))
}

func (tew *terminalEscaperWriter) printf(format string, a ...interface{}) {
	if tew.err != nil {
		return
	}
	_, tew.err = tew.replacer.WriteString(tew.w, fmt.Sprintf(format, a...))
}

// +build !windows

// Copyright 2013, Örjan Persson. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logging

import (
	"bytes"
	"fmt"
	"io"
	"log"
)

type color int

const (
	colorBlack = iota + 30
	colorRed
	colorGreen
	colorYellow
	colorBlue
	colorMagenta
	colorCyan
	colorWhite
)

var (
	colors = []string{
		CRITICAL: colorSeq(colorMagenta),
		ERROR:    colorSeq(colorRed),
		WARNING:  colorSeq(colorYellow),
		NOTICE:   colorSeq(colorGreen),
		DEBUG:    colorSeq(colorCyan),
	}
	boldcolors = []string{
		CRITICAL: colorSeqBold(colorMagenta),
		ERROR:    colorSeqBold(colorRed),
		WARNING:  colorSeqBold(colorYellow),
		NOTICE:   colorSeqBold(colorGreen),
		DEBUG:    colorSeqBold(colorCyan),
	}
)

// LogBackend utilizes the standard log module.
type LogBackend struct {
	Logger *log.Logger
	Color  bool
}

// NewLogBackend creates a new LogBackend.
func NewLogBackend(out io.Writer, prefix string, flag int) *LogBackend {
	return &LogBackend{Logger: log.New(out, prefix, flag)}
}

// Log implements the Backend interface.
func (b *LogBackend) Log(level Level, calldepth int, rec *Record) error {
	if b.Color {
		buf := &bytes.Buffer{}
		buf.Write([]byte(colors[level]))
		buf.Write([]byte(rec.Formatted(calldepth + 1)))
		buf.Write([]byte("\033[0m"))
		// For some reason, the Go logger arbitrarily decided "2" was the correct
		// call depth...
		return b.Logger.Output(calldepth+2, buf.String())
	}

	return b.Logger.Output(calldepth+2, rec.Formatted(calldepth+1))
}

func colorSeq(color color) string {
	return fmt.Sprintf("\033[%dm", int(color))
}

func colorSeqBold(color color) string {
	return fmt.Sprintf("\033[%d;1m", int(color))
}

func doFmtVerbLevelColor(layout string, level Level, output io.Writer) {
	if layout == "bold" {
		output.Write([]byte(boldcolors[level]))
	} else if layout == "reset" {
		output.Write([]byte("\033[0m"))
	} else {
		output.Write([]byte(colors[level]))
	}
}

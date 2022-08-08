// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testparsers

import (
	"bytes"

	"github.com/sirupsen/logrus"

	. "github.com/cilium/cilium/proxylib/proxylib"
)

//
// Line parser used for testing
//

type LineParserFactory struct{}

var lineParserFactory *LineParserFactory

func init() {
	logrus.Debug("init(): Registering lineParserFactory")
	RegisterParserFactory("test.lineparser", lineParserFactory)
}

type LineParser struct {
	connection *Connection
	inserted   bool
}

func (p *LineParserFactory) Create(connection *Connection) interface{} {
	logrus.Debugf("LineParserFactory: Create: %v", connection)
	return &LineParser{connection: connection}
}

func getLine(data [][]byte) ([]byte, bool) {
	var line bytes.Buffer
	for i, s := range data {
		index := bytes.IndexByte(s, '\n')
		if index < 0 {
			line.Write(s)
		} else {
			logrus.Debugf("getLine: unit: %d length: %d index: %d", i, len(s), index)
			line.Write(s[:index+1])
			return line.Bytes(), true
		}
	}
	return line.Bytes(), false
}

// Parses individual lines that must start with one of:
// "PASS" the line is passed
// "DROP" the line is dropped
// "INJECT" the line is injected in reverse direction
// "INSERT" the line is injected in current direction
func (p *LineParser) OnData(reply, endStream bool, data [][]byte) (OpType, int) {
	line, ok := getLine(data)
	line_len := len(line)

	if p.inserted {
		p.inserted = false
		return DROP, line_len
	}

	if !reply {
		logrus.Debugf("LineParser: Request: %s", line)
	} else {
		logrus.Debugf("LineParser: Response: %s", line)
	}

	if !ok {
		if line_len > 0 {
			// Partial line received, but no newline, ask for more
			return MORE, 1
		} else {
			// Nothing received, don't know if more will be coming; do nothing
			return NOP, 0
		}
	}

	if bytes.HasPrefix(line, []byte("PASS")) {
		return PASS, line_len
	}
	if bytes.HasPrefix(line, []byte("DROP")) {
		return DROP, line_len
	}
	if bytes.HasPrefix(line, []byte("INJECT")) {
		// Inject line in the reverse direction
		p.connection.Inject(!reply, []byte(line))
		// Drop the INJECT line in the current direction
		return DROP, line_len
	}
	if bytes.HasPrefix(line, []byte("INSERT")) {
		// Inject the line in the current direction
		p.connection.Inject(reply, []byte(line))
		// Drop the INJECT line in the current direction
		p.inserted = true
		return INJECT, line_len
	}

	return ERROR, int(ERROR_INVALID_FRAME_TYPE)
}

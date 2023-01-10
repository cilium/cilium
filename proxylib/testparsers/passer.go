// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testparsers

import (
	"github.com/sirupsen/logrus"

	. "github.com/cilium/cilium/proxylib/proxylib"
)

type PasserParserFactory struct{}

func init() {
	logrus.Debug("init(): Registering PasserParserFactory")
	RegisterParserFactory("test.passer", &PasserParserFactory{})
}

type PasserParser struct{}

func (p *PasserParserFactory) Create(connection *Connection) interface{} {
	// Reject invalid policy name for testing purposes
	if connection.PolicyName == "invalid-policy" {
		return nil
	}

	logrus.Debugf("PasserParserFactory: Create: %v", connection)
	return &PasserParser{}
}

// This simply passes all data in either direction.
func (p *PasserParser) OnData(reply, endStream bool, data [][]byte) (OpType, int) {
	n_bytes := 0
	for _, s := range data {
		n_bytes += len(s)
	}
	if n_bytes == 0 {
		return NOP, 0
	}
	if !reply {
		logrus.Debugf("PasserParser: Request: %d bytes", n_bytes)
	} else {
		logrus.Debugf("PasserParser: Response: %d bytes", n_bytes)
	}
	return PASS, n_bytes
}

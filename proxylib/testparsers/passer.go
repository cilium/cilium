// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package testparsers

import (
	. "github.com/cilium/cilium/proxylib/proxylib"

	log "github.com/sirupsen/logrus"
)

type PasserParserFactory struct{}

func init() {
	log.Debug("init(): Registering PasserParserFactory")
	RegisterParserFactory("test.passer", &PasserParserFactory{})
}

type PasserParser struct{}

func (p *PasserParserFactory) Create(connection *Connection) interface{} {
	// Reject invalid policy name for testing purposes
	if connection.PolicyName == "invalid-policy" {
		return nil
	}

	log.Debugf("PasserParserFactory: Create: %v", connection)
	return &PasserParser{}
}

//
// This simply passes all data in either direction.
//
func (p *PasserParser) OnData(reply, endStream bool, data [][]byte) (OpType, int) {
	n_bytes := 0
	for _, s := range data {
		n_bytes += len(s)
	}
	if n_bytes == 0 {
		return NOP, 0
	}
	if !reply {
		log.Debugf("PasserParser: Request: %d bytes", n_bytes)
	} else {
		log.Debugf("PasserParser: Response: %d bytes", n_bytes)
	}
	return PASS, n_bytes
}

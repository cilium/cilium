// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

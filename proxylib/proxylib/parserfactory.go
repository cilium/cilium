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

package proxylib

import (
	log "github.com/sirupsen/logrus"
)

// A parser instance is used for each connection. OnData will be called from a single thread only.
type Parser interface {
	OnData(reply, endStream bool, data [][]byte, offset int) (OpType, int)
}

type ParserFactory interface {
	Create(connection *Connection) Parser // must be thread safe!
}

// const after initialization
var parserFactories map[string]ParserFactory = make(map[string]ParserFactory)

// RegisterParserFactory adds a protocol parser factory to the map of known parsers.
// This is called from parser init() functions while we are still single-threaded
func RegisterParserFactory(name string, parserFactory ParserFactory) {
	log.Debugf("proxylib: Registering L7 parser: %v", name)
	parserFactories[name] = parserFactory
}

func GetParserFactory(name string) ParserFactory {
	return parserFactories[name]
}

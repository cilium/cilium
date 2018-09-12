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

package test

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	. "github.com/cilium/cilium/proxylib/proxylib"

	log "github.com/sirupsen/logrus"
)

//
// Header parser used for testing
//

type HeaderRule struct {
	name  string
	value string
}

func (rule *HeaderRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'
	items := strings.SplitN(data.(string), "=", 2)
	matches := len(items) == 2 && items[0] == rule.name && strings.HasPrefix(items[1], rule.value)

	if matches {
		log.Infof("HeaderRule: Rule matches %v", rule)
	} else {
		log.Infof("HeaderRule: Rule does not match %v", rule)
	}

	return matches
}

// L7HeaderRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func L7HeaderRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	httpRules := rule.GetHttpRules()
	if httpRules == nil {
		panic(fmt.Errorf("Can't get HTTP rules."))
	}
	var rules []L7NetworkPolicyRule
	for _, httpRule := range httpRules.HttpRules {
		for _, header := range httpRule.GetHeaders() {
			headerRule := HeaderRule{
				name:  header.Name,
				value: header.GetExactMatch(),
			}
			if headerRule.value == "" {
				panic(fmt.Errorf("Empty header value"))
			}
			rules = append(rules, &headerRule)
		}
	}
	log.Infof("Parsed HeaderRules: %v", rules)
	return rules
}

type HeaderParserFactory struct{}

var headerParserFactory *HeaderParserFactory

func init() {
	log.Info("init(): Registering headerParserFactory")
	RegisterParserFactory("test.headerparser", headerParserFactory)
	RegisterL7RuleParser("PortNetworkPolicyRule_HttpRules", L7HeaderRuleParser)
}

type HeaderParser struct {
	connection *Connection
}

func (p *HeaderParserFactory) Create(connection *Connection) Parser {
	log.Infof("HeaderParserFactory: Create: %v", connection)
	return &HeaderParser{connection: connection}
}

func getLine(data []string, offset uint32) (string, bool) {
	var line string
	for _, s := range data {
		index := strings.IndexByte(s[offset:], '\n')
		if index < 0 {
			line += s[offset:]
		} else {
			line += s[offset : offset+uint32(index)+1]
			return line, true
		}
		offset = 0
	}
	return line, false
}

//
// Parses individual lines that must start with one of:
// "PASS" the line is passed
// "DROP" the line is dropped
// "INJECT" the line is injected in reverse direction
// "INSERT" the line is injected in current direction
//
func (p *HeaderParser) OnData(reply, endStream bool, data []string, offset uint32) (OpType, uint32) {
	line, ok := getLine(data, offset)
	line_len := uint32(len(line))

	if !reply {
		log.Infof("HeaderParser: Request: %s", line)
	} else {
		log.Infof("HeaderParser: Response: %s", line)
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

	// Replies pass unconditionally
	if reply || p.connection.Matches(line) {
		p.connection.Log(cilium.EntryType_Request, &cilium.LogEntry_Http{&cilium.HttpLogEntry{Status: 200}})
		return PASS, line_len
	}

	// Inject Error response to the reverse direction
	p.connection.Inject(!reply, []byte(fmt.Sprintf("Line dropped: %s", line)))
	// Drop the line in the current direction
	p.connection.Log(cilium.EntryType_Denied, &cilium.LogEntry_Http{&cilium.HttpLogEntry{Status: 403}})
	return DROP, line_len
}

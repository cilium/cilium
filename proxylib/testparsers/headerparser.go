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

//
// Accompanying file `headerparser.policy` contains an example policy
// for this protocol. Install it with:
// $ cilium policy import proxylib/testparsers/headerparser.policy
//

package testparsers

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
	hasPrefix string
	contains  string
	hasSuffix string
}

// Matches returns true if the HeaderRule matches
func (rule *HeaderRule) Matches(data interface{}) bool {
	log.Infof("headerparser checking rule %v", *rule)

	// Trim whitespace from both ends
	str := strings.TrimSpace(data.(string))

	if rule.hasPrefix != "" && !strings.HasPrefix(str, rule.hasPrefix) {
		log.Infof("headerparser HasPrefix %s does not match %s", str, rule.hasPrefix)
		return false
	}

	if rule.contains != "" && !strings.Contains(str, rule.contains) {
		log.Infof("headerparser Contains %s does not match %s", str, rule.contains)
		return false
	}

	if rule.hasSuffix != "" && !strings.HasSuffix(str, rule.hasSuffix) {
		log.Infof("headerparser HasSuffix %s does not match %s", str, rule.hasSuffix)
		return false
	}
	log.Info("headerparser rule matched!")

	return true
}

// L7HeaderRuleParser parses protobuf L7 rules to and array of HeaderRules
// May panic
func L7HeaderRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		panic(fmt.Errorf("Can't get L7 rules."))
	}
	var rules []L7NetworkPolicyRule
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var hr HeaderRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "prefix":
				hr.hasPrefix = v
			case "contains":
				hr.contains = v
			case "suffix":
				hr.hasSuffix = v
			default:
				panic(fmt.Errorf("Unsupported key: %s", k))
			}
		}
		log.Infof("Parsed HeaderRule pair: %v", hr)
		rules = append(rules, &hr)
	}
	return rules
}

type HeaderParserFactory struct{}

var headerParserFactory *HeaderParserFactory

const (
	parserName = "test.headerparser"
)

func init() {
	log.Info("init(): Registering headerParserFactory")
	RegisterParserFactory(parserName, headerParserFactory)
	RegisterL7RuleParser(parserName, L7HeaderRuleParser)
}

type HeaderParser struct {
	connection *Connection
}

func (p *HeaderParserFactory) Create(connection *Connection) Parser {
	log.Infof("HeaderParserFactory: Create: %v", connection)
	return &HeaderParser{connection: connection}
}

//
// Parses individual lines and verifies them against the policy
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
		p.connection.Log(cilium.EntryType_Request,
			&cilium.LogEntry_GenericL7{
				&cilium.L7LogEntry{
					Proto: parserName,
					Fields: map[string]string{
						"status": "PASS",
					},
				},
			})
		return PASS, line_len
	}

	// Inject Error response to the reverse direction
	p.connection.Inject(!reply, []byte(fmt.Sprintf("Line dropped: %s", line)))
	// Drop the line in the current direction
	p.connection.Log(cilium.EntryType_Denied,
		&cilium.LogEntry_GenericL7{
			&cilium.L7LogEntry{
				Proto: parserName,
				Fields: map[string]string{
					"status": "DROP",
				},
			},
		})

	return DROP, line_len
}

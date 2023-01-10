// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//
// Accompanying file `headerparser.policy` contains an example policy
// for this protocol. Install it with:
// $ cilium policy import proxylib/testparsers/headerparser.policy
//

package testparsers

import (
	"bytes"
	"fmt"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"

	. "github.com/cilium/cilium/proxylib/proxylib"
)

//
// Header parser used for testing
//

type HeaderRule struct {
	hasPrefix []byte
	contains  []byte
	hasSuffix []byte
}

// Matches returns true if the HeaderRule matches
func (rule *HeaderRule) Matches(data interface{}) bool {
	logrus.Debugf("headerparser checking rule %v", *rule)

	// Trim whitespace from both ends
	bs := bytes.TrimSpace(data.([]byte))

	if len(rule.hasPrefix) > 0 && !bytes.HasPrefix(bs, rule.hasPrefix) {
		logrus.Debugf("headerparser HasPrefix %s does not match %s", bs, rule.hasPrefix)
		return false
	}

	if len(rule.contains) > 0 && !bytes.Contains(bs, rule.contains) {
		logrus.Debugf("headerparser Contains %s does not match %s", bs, rule.contains)
		return false
	}

	if len(rule.hasSuffix) > 0 && !bytes.HasSuffix(bs, rule.hasSuffix) {
		logrus.Debugf("headerparser HasSuffix %s does not match %s", bs, rule.hasSuffix)
		return false
	}
	logrus.Debug("headerparser rule matched!")

	return true
}

// L7HeaderRuleParser parses protobuf L7 rules to and array of HeaderRules
func L7HeaderRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return nil
	}

	allowRules := l7Rules.GetL7AllowRules()
	rules := make([]L7NetworkPolicyRule, 0, len(allowRules))
	for _, l7Rule := range allowRules {
		var hr HeaderRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "prefix":
				hr.hasPrefix = []byte(v)
			case "contains":
				hr.contains = []byte(v)
			case "suffix":
				hr.hasSuffix = []byte(v)
			default:
				ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		logrus.Debugf("Parsed HeaderRule pair: %v", hr)
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
	logrus.Debug("init(): Registering headerParserFactory")
	RegisterParserFactory(parserName, headerParserFactory)
	RegisterL7RuleParser(parserName, L7HeaderRuleParser)
}

type HeaderParser struct {
	connection *Connection
}

func (p *HeaderParserFactory) Create(connection *Connection) interface{} {
	logrus.Debugf("HeaderParserFactory: Create: %v", connection)
	return &HeaderParser{connection: connection}
}

// Parses individual lines and verifies them against the policy
func (p *HeaderParser) OnData(reply, endStream bool, data [][]byte) (OpType, int) {
	line, ok := getLine(data)
	line_len := len(line)

	if !reply {
		logrus.Debugf("HeaderParser: Request: %s", line)
	} else {
		logrus.Debugf("HeaderParser: Response: %s", line)
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
				GenericL7: &cilium.L7LogEntry{
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
			GenericL7: &cilium.L7LogEntry{
				Proto: parserName,
				Fields: map[string]string{
					"status": "DROP",
				},
			},
		})

	return DROP, line_len
}

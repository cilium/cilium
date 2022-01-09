// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package tidbsql

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/cilium/cilium/proxylib/proxylib"
	cilium "github.com/cilium/proxy/go/cilium/api"
	log "github.com/sirupsen/logrus"
)

type tidbsqlRule struct {
	actionExact        string
	tableRegexCompiled *regexp.Regexp
}

type tidbsqlRequestData struct {
	action string
	table  string
}

func (rule *tidbsqlRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	reqData, ok := data.(tidbsqlRequestData)
	regexStr := ""
	if rule.tableRegexCompiled != nil {
		regexStr = rule.tableRegexCompiled.String()
	}

	if !ok {
		log.Warning("Matches() called with type other than TiDBSQLRequestData")
		return false
	}
	if len(rule.actionExact) > 0 && rule.actionExact != reqData.action {
		log.Infof("TiDBSQLRule: cmd mismatch %s, %s", rule.actionExact, reqData.action)
		return false
	}
	if rule.tableRegexCompiled != nil &&
		!rule.tableRegexCompiled.MatchString(reqData.table) {
		log.Infof("TiDBSQLRule: database mismatch %s, %s", rule.tableRegexCompiled.String(), reqData.table)
		return false
	}
	log.Infof("policy match for rule: '%s' '%s'", rule.actionExact, regexStr)
	return true
}

// ruleParser parses protobuf L7 rules to enforcement objects
// May panic
func ruleParser(rule *cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return nil
	}

	allowRules := l7Rules.GetL7AllowRules()
	rules := make([]proxylib.L7NetworkPolicyRule, 0, len(allowRules))
	for _, l7Rule := range allowRules {
		var rr tidbsqlRule
		for k, v := range l7Rule.Rule {
			log.Infof("k value %v", k)
			switch k {
			case "select":
				rr.actionExact = "select"
				if v != "" {
					rr.tableRegexCompiled = regexp.MustCompile(v)
				}
			case "insert":
				rr.actionExact = "insert"
				if v != "" {
					rr.tableRegexCompiled = regexp.MustCompile(v)
				}
			case "update":
				rr.actionExact = "update"
				if v != "" {
					rr.tableRegexCompiled = regexp.MustCompile(v)
				}
			case "delete":
				rr.actionExact = "delete"
				if v != "" {
					rr.tableRegexCompiled = regexp.MustCompile(v)
				}
			default:
				proxylib.ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if rr.actionExact != "" &&
			rr.actionExact != "select" &&
			rr.actionExact != "insert" &&
			rr.actionExact != "update" &&
			rr.actionExact != "delete" {
			proxylib.ParseError(fmt.Sprintf("Unable to parse L7 tidbsql rule with invalid action: '%s'", rr.actionExact), rule)
		}
		regexStr := ""
		if rr.tableRegexCompiled != nil {
			regexStr = rr.tableRegexCompiled.String()
		}
		log.Infof("Parsed rule '%s' '%s'", rr.actionExact, regexStr)
		rules = append(rules, &rr)
	}
	return rules
}

type factory struct{}

func init() {
	log.Info("init(): Registering tidbsqlParserFactory")
	proxylib.RegisterParserFactory("tidbsql", &factory{})
	proxylib.RegisterL7RuleParser("tidbsql", ruleParser)
}

type parser struct {
	connection *proxylib.Connection
}

func (f *factory) Create(connection *proxylib.Connection) interface{} {
	log.Infof("TiDBSQLParserFactory: Create: %v", connection)
	return &parser{connection: connection}
}

func (p *parser) OnData(reply, endStream bool, dataArray [][]byte) (proxylib.OpType, int) {
	identity := p.connection.SrcId
	log.Info("Identity:", identity)

	// inefficient, but simple
	data := string(bytes.Join(dataArray, []byte{}))

	log.Infof("OnData: '%s', len: %d", data, len(data))
	if endStream || len(data) == 0 {
		log.Info("stream ended, nothing need to be done, waiting client to issue new query")
		return proxylib.NOP, 0
	}

	if reply {
		log.Infof("passing %d bytes for reply", len(data))
		return proxylib.PASS, len(data)
	}

	bodyLen := data[0]
	// 0x0f, 0x00, 0x00, 0x00, 0x03, show databases 0~18, msgLen=15, msgLen+4=19 , len(d)=15
	if len(data[4:]) < int(bodyLen) {
		log.Infof("Not enough data, requesting more bytes")
		return proxylib.MORE, int(bodyLen) - len(data[4:])
	}

	body := data[4 : bodyLen+4] // read single request
	msgLen := len(body) + 4
	cmd := body[0]
	// we only process COM_QUERY, all other traffic should pass
	if cmd != 0x03 {
		log.Infof("passing %d bytes for non COM_QUERY", msgLen)
		return proxylib.PASS, msgLen
	}

	stmt := body[1:] // sql statement

	log.Infof("passing %d bytes for sql statement: %s", msgLen, stmt)
	return proxylib.PASS, msgLen
}

func verifyQuery() bool {
	return true
}

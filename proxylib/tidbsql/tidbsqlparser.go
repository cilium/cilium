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
	cmdExact          string
	fileRegexCompiled *regexp.Regexp
}

type tidbsqlRequestData struct {
	cmd  string
	file string
}

func (rule *tidbsqlRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	reqData, ok := data.(tidbsqlRequestData)
	regexStr := ""
	if rule.fileRegexCompiled != nil {
		regexStr = rule.fileRegexCompiled.String()
	}

	if !ok {
		log.Warning("Matches() called with type other than TiDBSQLRequestData")
		return false
	}
	if len(rule.cmdExact) > 0 && rule.cmdExact != reqData.cmd {
		log.Infof("TiDBSQLRule: cmd mismatch %s, %s", rule.cmdExact, reqData.cmd)
		return false
	}
	if rule.fileRegexCompiled != nil &&
		!rule.fileRegexCompiled.MatchString(reqData.file) {
		log.Infof("TiDBSQLRule: file mismatch %s, %s", rule.fileRegexCompiled.String(), reqData.file)
		return false
	}
	log.Infof("policy match for rule: '%s' '%s'", rule.cmdExact, regexStr)
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
			case "cmd":
				rr.cmdExact = v
			case "file":
				if v != "" {
					rr.fileRegexCompiled = regexp.MustCompile(v)
				}
			default:
				proxylib.ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if rr.cmdExact != "" &&
			rr.cmdExact != "READ" &&
			rr.cmdExact != "WRITE" &&
			rr.cmdExact != "HALT" &&
			rr.cmdExact != "RESET" {
			proxylib.ParseError(fmt.Sprintf("Unable to parse L7 tidbsql rule with invalid cmd: '%s'", rr.cmdExact), rule)
		}
		if (rr.fileRegexCompiled != nil) && !(rr.cmdExact == "" || rr.cmdExact == "READ" || rr.cmdExact == "WRITE") {
			proxylib.ParseError(fmt.Sprintf("Unable to parse L7 tidbsql rule, cmd '%s' is not compatible with 'file'", rr.cmdExact), rule)
		}
		regexStr := ""
		if rr.fileRegexCompiled != nil {
			regexStr = rr.fileRegexCompiled.String()
		}
		log.Infof("Parsed rule '%s' '%s'", rr.cmdExact, regexStr)
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

	msgLen := data[0]
	d := data[4:]
	if len(d) < int(msgLen) {
		log.Infof("Not enough data, requesting more bytes")
		return proxylib.MORE, int(msgLen) - len(d)
	}

	if reply {
		log.Infof("passing %d bytes for reply", len(data))
		return proxylib.PASS, len(data)
	}

	cmd := d[0]
	// we only process COM_QUERY, all other traffic should pass
	if int(cmd) != 3 {
		log.Infof("passing %d bytes for non COM_QUERY", len(data))
		return proxylib.PASS, len(data)
	}

	stmt := d[1:] // sql statement

	log.Infof("passing %d bytes for sql statement: %s", len(data), stmt)

	// TODO: define a deny check when querying datas from some database
	matches := verifyQuery(stmt, rule)
	if !matches {
		// TODO: construct a MySQL style unauthorized error
		p.connection.Inject(true, []byte("ERROR\r\n"))
		log.Infof("Policy mismatch, dropping %d bytes", len(data))
		return proxylib.DROP, len(data)
	}

	return proxylib.PASS, len(data)
}

func verifyQuery() bool {
	
}
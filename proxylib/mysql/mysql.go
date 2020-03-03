// Copyright 2020 Authors of Cilium
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

package mysql

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/cilium/proxylib/proxylib"
	cilium "github.com/cilium/proxy/go/cilium/api"

	log "github.com/sirupsen/logrus"
	"vitess.io/vitess/go/vt/sqlparser"
)

//
// MySQL Parser
//
// This is a toy protocol to teach people how to build a Cilium golang proxy parser.
//

// Current MySQL parser supports filtering on a basic text protocol with 4 request-types:
// "READ <filename>\r\n"  - Read a file from the Droid
// "WRITE <filename>\r\n" - Write a file to the Droid
// "HALT\r\n" - Shutdown the Droid
// "RESET\r\n" - Reset the Droid to factory settings
//
// Replies include a status of either "OK\r\n", "ERROR\r\n" for "WRITE", "HALT", or "RESET".
//  Replies for "READ" are either "OK <filedata>\r\n" or "ERROR\r\n".
//
//
// Policy Examples:
// {cmd : "READ"}  - Allow all reads, no other commands.
// {cmd : "READ", file : "/public/.*" }  - Allow reads that are in the public directory
// {file : "/public/.*" } - Allow read/write on the public directory.
// {cmd : "HALT"} - Allow shutdown, but no other actions.

const (
	invalid_action  = 0
	actionWithTable = 1
	actionNoTable   = 2
)

var query_actionMap = map[string]int{
	"select": actionWithTable,
	"delete": actionWithTable,
}

type mysqlRule struct {
	queryActionExact   string
	tableRegexCompiled *regexp.Regexp
}

type mysqlRequestData struct {
	cmd  string
	file string
}

func (rule *mysqlRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	sql, ok := data.(string)
	if !ok {
		log.Warning("Matches() called with type other than string")
		return false
	}
	tree, err := sqlparser.Parse(sql)
	if err != nil {
		log.Warning("could not parse query")
		return false
	}
	log.Debugf("node: %v", tree)
	log.Debugf("Policy Match test for '%s'", sql)
	regexStr := ""
	if rule.tableRegexCompiled != nil {
		regexStr = rule.tableRegexCompiled.String()
	}

	if !ok {
		log.Warning("Matches() called with type other than MysqlRequestData")
		return false
	}
	if len(rule.queryActionExact) > 0 && rule.queryActionExact != "" {
		log.Debugf("R2d2Rule: cmd mismatch %s, %s", rule.queryActionExact, "")
		return false
	}
	if rule.tableRegexCompiled != nil &&
		!rule.tableRegexCompiled.MatchString("") {
		log.Debugf("R2d2Rule: file mismatch %s, %s", rule.tableRegexCompiled.String())
		return false
	}
	log.Debugf("policy match for rule: '%s' '%s'", rule.queryActionExact, regexStr)
	return true
}

// ruleParser parses protobuf L7 rules to enforcement objects
// May panic
func ruleParser(rule *cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	var rules []proxylib.L7NetworkPolicyRule
	if l7Rules == nil {
		return rules
	}
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var mr mysqlRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "query_action":
				mr.queryActionExact = v
			case "query_table":
				if v != "" {
					mr.tableRegexCompiled = regexp.MustCompile(v)
				}
			default:
				proxylib.ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if mr.queryActionExact != "" {
			proxylib.ParseError(fmt.Sprintf("Unable to parse L7 MySQL rule with invalid action: '%s'", mr.queryActionExact), rule)
		}
		if (mr.tableRegexCompiled != nil) && !(mr.queryActionExact == "") {
			proxylib.ParseError(fmt.Sprintf("Unable to parse L7 Mysql rule, cmd '%s' is not compatible with 'query'", mr.queryActionExact), rule)
		}
		regexStr := ""
		if mr.tableRegexCompiled != nil {
			regexStr = mr.tableRegexCompiled.String()
		}
		log.Debugf("Parsed rule '%s' '%s'", mr.queryActionExact, regexStr)
		rules = append(rules, &mr)
	}
	return rules
}

type factory struct{}

func init() {
	log.Debug("init(): Registering mysqlParserFactory")
	proxylib.RegisterParserFactory("mysql", &factory{})
	proxylib.RegisterL7RuleParser("mysql", ruleParser)
}

type parser struct {
	connection *proxylib.Connection
	inserted   bool
}

func (f *factory) Create(connection *proxylib.Connection) proxylib.Parser {
	log.Debugf("MysqlParserFactory: Create: %v", connection)

	return &parser{connection: connection}
}

func (p *parser) OnData(reply, endStream bool, dataArray [][]byte) (proxylib.OpType, int) {

	// inefficient, but simple
	data := string(bytes.Join(dataArray, []byte{}))

	log.Debugf("OnData: '%s'", data)
	msgLen := strings.Index(data, "\r\n")
	if msgLen < 0 {
		// No delimiter, request more data
		log.Debugf("No delimiter found, requesting more bytes")
		return proxylib.MORE, 1
	}

	msgStr := data[:msgLen] // read single request
	msgLen += 2             // include "\r\n"
	log.Debugf("Request = '%s'", msgStr)

	// we don't process reply traffic for now
	if reply {
		log.Debugf("reply, passing %d bytes", msgLen)
		return proxylib.PASS, msgLen
	}

	matches := true
	access_log_entry_type := cilium.EntryType_Request

	if !p.connection.Matches(msgStr) {
		matches = false
		access_log_entry_type = cilium.EntryType_Denied
	}

	p.connection.Log(access_log_entry_type,
		&cilium.LogEntry_GenericL7{
			GenericL7: &cilium.L7LogEntry{
				Proto: "r2d2",
				Fields: map[string]string{
					"sql": msgStr,
				},
			},
		})

	if !matches {
		p.connection.Inject(true, []byte("ERROR\r\n"))
		log.Debugf("Policy mismatch, dropping %d bytes", msgLen)
		return proxylib.DROP, msgLen
	}

	return proxylib.PASS, msgLen
}

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

package r2d2

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/cilium/proxylib/proxylib"

	"github.com/cilium/proxy/go/cilium/api"
	log "github.com/sirupsen/logrus"
)

//
// R2D2 Parser
//
// This is a toy protocol to teach people how to build a Cilium golang proxy parser.
//

// Current R2D2 parser supports filtering on a basic text protocol with 4 request-types:
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

type r2d2Rule struct {
	cmdExact          string
	fileRegexCompiled *regexp.Regexp
}

type r2d2RequestData struct {
	cmd  string
	file string
}

func (rule *r2d2Rule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	reqData, ok := data.(r2d2RequestData)
	regexStr := ""
	if rule.fileRegexCompiled != nil {
		regexStr = rule.fileRegexCompiled.String()
	}

	if !ok {
		log.Warning("Matches() called with type other than R2d2RequestData")
		return false
	}
	if len(rule.cmdExact) > 0 && rule.cmdExact != reqData.cmd {
		log.Debugf("R2d2Rule: cmd mismatch %s, %s", rule.cmdExact, reqData.cmd)
		return false
	}
	if rule.fileRegexCompiled != nil &&
		!rule.fileRegexCompiled.MatchString(reqData.file) {
		log.Debugf("R2d2Rule: file mismatch %s, %s", rule.fileRegexCompiled.String(), reqData.file)
		return false
	}
	log.Debugf("policy match for rule: '%s' '%s'", rule.cmdExact, regexStr)
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
		var rr r2d2Rule
		for k, v := range l7Rule.Rule {
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
			proxylib.ParseError(fmt.Sprintf("Unable to parse L7 r2d2 rule with invalid cmd: '%s'", rr.cmdExact), rule)
		}
		if (rr.fileRegexCompiled != nil) && !(rr.cmdExact == "" || rr.cmdExact == "READ" || rr.cmdExact == "WRITE") {
			proxylib.ParseError(fmt.Sprintf("Unable to parse L7 r2d2 rule, cmd '%s' is not compatible with 'file'", rr.cmdExact), rule)
		}
		regexStr := ""
		if rr.fileRegexCompiled != nil {
			regexStr = rr.fileRegexCompiled.String()
		}
		log.Debugf("Parsed rule '%s' '%s'", rr.cmdExact, regexStr)
		rules = append(rules, &rr)
	}
	return rules
}

type factory struct{}

func init() {
	log.Debug("init(): Registering r2d2ParserFactory")
	proxylib.RegisterParserFactory("r2d2", &factory{})
	proxylib.RegisterL7RuleParser("r2d2", ruleParser)
}

type parser struct {
	connection *proxylib.Connection
}

func (f *factory) Create(connection *proxylib.Connection) interface{} {
	log.Debugf("R2d2ParserFactory: Create: %v", connection)

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

	fields := strings.Split(msgStr, " ")
	if len(fields) < 1 {
		return proxylib.ERROR, int(proxylib.ERROR_INVALID_FRAME_TYPE)
	}
	reqData := r2d2RequestData{cmd: fields[0]}
	if len(fields) == 2 {
		reqData.file = fields[1]
	}

	matches := true
	access_log_entry_type := cilium.EntryType_Request

	if !p.connection.Matches(reqData) {
		matches = false
		access_log_entry_type = cilium.EntryType_Denied
	}

	p.connection.Log(access_log_entry_type,
		&cilium.LogEntry_GenericL7{
			GenericL7: &cilium.L7LogEntry{
				Proto: "r2d2",
				Fields: map[string]string{
					"cmd":  reqData.cmd,
					"file": reqData.file,
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

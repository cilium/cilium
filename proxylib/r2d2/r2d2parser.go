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

	"github.com/cilium/cilium/pkg/envoy/cilium"
	. "github.com/cilium/cilium/proxylib/proxylib"

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

type R2d2Rule struct {
	cmdExact          string
	fileRegexCompiled *regexp.Regexp
}

type R2d2RequestData struct {
	cmd  string
	file string
}

func (rule *R2d2Rule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	reqData, ok := data.(R2d2RequestData)
	regexStr := ""
	if rule.fileRegexCompiled != nil {
		regexStr = rule.fileRegexCompiled.String()
	}

	if !ok {
		log.Warning("Matches() called with type other than R2d2RequestData")
		return false
	}
	if len(rule.cmdExact) > 0 && rule.cmdExact != reqData.cmd {
		log.Infof("R2d2Rule: cmd mismatch %s, %s", rule.cmdExact, reqData.cmd)
		return false
	}
	if rule.fileRegexCompiled != nil &&
		!rule.fileRegexCompiled.MatchString(reqData.file) {
		log.Infof("R2d2Rule: file mismatch %s, %s", rule.fileRegexCompiled.String(), reqData.file)
		return false
	}
	log.Infof("policy match for rule: '%s' '%s'", rule.cmdExact, regexStr)
	return true
}

// R2d2RuleParser parses protobuf L7 rules to enforcement objects
// May panic
func R2d2RuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	var rules []L7NetworkPolicyRule
	if l7Rules == nil {
		return rules
	}
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var rr R2d2Rule
		for k, v := range l7Rule.Rule {
			switch k {
			case "cmd":
				rr.cmdExact = v
			case "file":
				if v != "" {
					rr.fileRegexCompiled = regexp.MustCompile(v)
				}
			default:
				ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if rr.cmdExact != "" &&
			rr.cmdExact != "READ" &&
			rr.cmdExact != "WRITE" &&
			rr.cmdExact != "HALT" &&
			rr.cmdExact != "RESET" {
			ParseError(fmt.Sprintf("Unable to parse L7 r2d2 rule with invalid cmd: '%s'", rr.cmdExact), rule)
		}
		if (rr.fileRegexCompiled != nil) && !(rr.cmdExact == "" || rr.cmdExact == "READ" || rr.cmdExact == "WRITE") {
			ParseError(fmt.Sprintf("Unable to parse L7 r2d2 rule, cmd '%s' is not compatible with 'file'", rr.cmdExact), rule)
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

type R2d2ParserFactory struct{}

var r2d2ParserFactory *R2d2ParserFactory

func init() {
	log.Info("init(): Registering r2d2ParserFactory")
	RegisterParserFactory("r2d2", r2d2ParserFactory)
	RegisterL7RuleParser("r2d2", R2d2RuleParser)
}

type R2d2Parser struct {
	connection *Connection
	inserted   bool
}

func (pf *R2d2ParserFactory) Create(connection *Connection) Parser {
	log.Debugf("R2d2ParserFactory: Create: %v", connection)

	p := R2d2Parser{connection: connection}
	return &p
}

func (p *R2d2Parser) OnData(reply, endStream bool, dataArray [][]byte) (OpType, int) {

	// inefficient, but simple
	data := string(bytes.Join(dataArray, []byte{}))

	log.Infof("OnData: '%s'", data)

	if !strings.Contains(data, "\r\n") {
		// No delimiter, request more data
		log.Infof("No delimiter found, requesting more bytes")
		return MORE, 1
	}

	// read single request
	msgStr := strings.Split(data, "\r\n")[0]
	msgLen := len(msgStr) + 2
	log.Infof("Request = '%s'", msgStr)

	// we don't process reply traffic for now
	if reply {
		log.Infof("reply, passing %d bytes", msgLen)
		return PASS, msgLen
	}

	fileStr := ""
	fields := strings.Split(msgStr, " ")
	if len(fields) == 0 {
		return ERROR, int(ERROR_INVALID_FRAME_TYPE)
	}
	if len(fields) == 2 {
		fileStr = fields[1]
	}
	reqData := R2d2RequestData{
		cmd:  fields[0],
		file: fileStr,
	}

	matches := true
	access_log_entry_type := cilium.EntryType_Request

	if !p.connection.Matches(reqData) {
		matches = false
		access_log_entry_type = cilium.EntryType_Denied
	}

	p.connection.Log(access_log_entry_type,
		&cilium.LogEntry_GenericL7{
			&cilium.L7LogEntry{
				Proto: "r2d2",
				Fields: map[string]string{
					"cmd":  reqData.cmd,
					"file": reqData.file,
				},
			},
		})

	if !matches {
		p.connection.Inject(true, []byte("ERROR\r\n"))
		log.Infof("Policy mismatch, dropping %d bytes", msgLen)
		return DROP, msgLen
	}

	return PASS, msgLen
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package tidbmultitenant

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/cilium/proxylib/proxylib"
	cilium "github.com/cilium/proxy/go/cilium/api"

	log "github.com/sirupsen/logrus"
)

type tidbmultitenantRule struct {
	cmdExact          string
	fileRegexCompiled *regexp.Regexp
}

type tidbmultitenantRequestData struct {
	cmd  string
	file string
}

func (rule *tidbmultitenantRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	reqData, ok := data.(tidbmultitenantRequestData)
	regexStr := ""
	if rule.fileRegexCompiled != nil {
		regexStr = rule.fileRegexCompiled.String()
	}

	if !ok {
		log.Warning("Matches() called with type other than TiDBMultiTenantRequestData")
		return false
	}
	if len(rule.cmdExact) > 0 && rule.cmdExact != reqData.cmd {
		log.Infof("TiDBMultiTenantRule: cmd mismatch %s, %s", rule.cmdExact, reqData.cmd)
		return false
	}
	if rule.fileRegexCompiled != nil &&
		!rule.fileRegexCompiled.MatchString(reqData.file) {
		log.Infof("TiDBMultiTenantRule: file mismatch %s, %s", rule.fileRegexCompiled.String(), reqData.file)
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
		var rr tidbmultitenantRule
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
			proxylib.ParseError(fmt.Sprintf("Unable to parse L7 tidbmultitenant rule with invalid cmd: '%s'", rr.cmdExact), rule)
		}
		if (rr.fileRegexCompiled != nil) && !(rr.cmdExact == "" || rr.cmdExact == "READ" || rr.cmdExact == "WRITE") {
			proxylib.ParseError(fmt.Sprintf("Unable to parse L7 tidbmultitenant rule, cmd '%s' is not compatible with 'file'", rr.cmdExact), rule)
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
	log.Info("init(): Registering tidbmultitenantParserFactory")
	proxylib.RegisterParserFactory("tidbmultitenant", &factory{})
	proxylib.RegisterL7RuleParser("tidbmultitenant", ruleParser)
}

type parser struct {
	connection *proxylib.Connection
}

func (f *factory) Create(connection *proxylib.Connection) interface{} {
	log.Infof("TiDBMultiTenantParserFactory: Create: %v", connection)
	return &parser{connection: connection}
}

func (p *parser) OnData(reply, endStream bool, dataArray [][]byte) (proxylib.OpType, int) {
	log.Infof("srcid: %v, destid: %v", p.connection.SrcId, p.connection.DstId)

	// inefficient, but simple
	data := string(bytes.Join(dataArray, []byte{}))

	log.Infof("OnData: '%s'", data)
	msgLen := strings.Index(data, "\r\n")
	if msgLen < 0 {
		// No delimiter, request more data
		log.Infof("No delimiter found, requesting more bytes")
		return proxylib.MORE, 1
	}

	msgStr := data[:msgLen] // read single request
	msgLen += 2             // include "\r\n"
	log.Infof("Request = '%s'", msgStr)

	// we don't process reply traffic for now
	if reply {
		log.Infof("reply, passing %d bytes", msgLen)
		return proxylib.PASS, msgLen
	}

	fields := strings.Split(msgStr, " ")
	if len(fields) < 1 {
		return proxylib.ERROR, int(proxylib.ERROR_INVALID_FRAME_TYPE)
	}
	reqData := tidbmultitenantRequestData{cmd: fields[0]}
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
				Proto: "tidbmultitenant",
				Fields: map[string]string{
					"cmd":  reqData.cmd,
					"file": reqData.file,
				},
			},
		})

	if !matches {
		p.connection.Inject(true, []byte("ERROR\r\n"))
		log.Infof("Policy mismatch, dropping %d bytes", msgLen)
		return proxylib.DROP, msgLen
	}

	return proxylib.PASS, msgLen
}

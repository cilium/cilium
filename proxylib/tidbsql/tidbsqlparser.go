// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package tidbsql

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/cilium/cilium/proxylib/proxylib"
	sqlparser "github.com/cilium/cilium/proxylib/tidbsql/pkg/sqlparser"
	cilium "github.com/cilium/proxy/go/cilium/api"
	log "github.com/sirupsen/logrus"
)

type tidbsqlRule struct {
	actionExact        string
	tableRegexCompiled *regexp.Regexp
}

func (rule *tidbsqlRule) Matches(sql interface{}) bool {
	reqAction, reqDatabase, reqTable, _ := sqlparser.GetDatabaseTables(sql.(string))
	regexStr := ""
	if rule.tableRegexCompiled != nil {
		regexStr = rule.tableRegexCompiled.String()
	}

	if len(rule.actionExact) > 0 && rule.actionExact != reqAction {
		log.Infof("TiDBSQLRule: cmd mismatch %s, %s", rule.actionExact, reqAction)
		return false
	}

	tName := reqTable
	if reqDatabase != "" {
		tName = fmt.Sprintf("%s.%s", reqDatabase, reqTable)
	}

	if rule.tableRegexCompiled != nil && !rule.tableRegexCompiled.MatchString(tName) {
		log.Infof("TiDBSQLRule: database mismatch %s, %s", rule.tableRegexCompiled.String(), tName)
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

	matches := true
	if !p.connection.Matches(fmt.Sprintf("%v", stmt)) {
		matches = false
	}
	if !matches {
		// TODO: use MySQL ERROR packet
		p.connection.Inject(true, constructErrorMessage("access denied from network policy", false))
		log.Infof("Policy mismatch, dropping %d bytes", msgLen)
		return proxylib.DROP, msgLen
	}
	log.Infof("passing %d bytes for sql statement: %s", msgLen, stmt)
	return proxylib.PASS, msgLen
}

func constructErrorMessage(errorMessage string, dbErr bool) []byte {
	// payloadLength is a fixed length integer: https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::FixedLengthInteger
	// nodatabaseSelectedErr = []byte{29 0 0 1 255 22 4 35 51 68 48 48 48 48 78 111 32 100 97 116 97 98 97 115 101 32 115 101 108 101 99 116 101 100}
	// return nodatabaseSelectedErr

	// https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html

	sequenceID := 1
	header := []byte{0xff} // for error packet, it's 0xff
	var errCode []byte
	// handle db err and table err
	if dbErr {
		errCode = []byte{0x14, 0x04} // 1044, 42000 ER_DBACCESS_DENIED_ERROR
	} else {
		errCode = []byte{0x12, 0x04} // 1042, 42000 ER_TABLEACCESS_DENIED_ERROR
	}
	sqlStateMarker := []byte{0x23} // TODO: why this value

	sqlState := []byte("42000") // 42000
	payload := []byte{}
	payload = append(payload, header...)
	payload = append(payload, errCode...)
	payload = append(payload, sqlStateMarker...)
	payload = append(payload, sqlState...)
	payload = append(payload, []byte(errorMessage)...)
	payloadLength := len(payload)
	return append([]byte{byte(payloadLength), 0x00, 0x00, byte(sequenceID)}, payload...)
}

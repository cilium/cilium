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

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	. "github.com/cilium/cilium/proxylib/proxylib"

	log "github.com/sirupsen/logrus"
)

//
// Cassandra v3/v4 Parser
//
// Spec: https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v4.spec
//

// Current Cassandra parser supports filtering on 'opcode' and if the opcode is 'query-like'
// (i.e., opcode 'query', 'prepare', 'batch', we then match on query_action and query_table.
// Examples:
// opcode = 'options'
// opcode = 'execute'
// opcode = 'query', query_action = 'select', query_table = 'system.*'
// opcode = 'query', query_action = 'insert', query_table = 'covalent.l3_l4_flows'
// opcode = 'prepare', query_action = 'select', query_table = 'covalent.foo'
// opcode = 'batch', query_action = 'insert', query_table = 'covalent.foo'
//
// Batch requests are logged as invidual queries, but an entire batch request will be allowed
// only if all requests are allowed.

// There are known changes in protocol v2 that are not compatible with this parser, see the
// the "Changes from v2" in https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v3.spec

type CassandraRule struct {
	opcode_exact         string
	query_action_exact   string
	table_regex_compiled *regexp.Regexp
}

func (rule *CassandraRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	path := data.(string)
	log.Infof("Policy Match test for '%s'", path)
	regex_str := ""
	if rule.table_regex_compiled != nil {
		regex_str = rule.table_regex_compiled.String()
	}
	log.Infof("Rule: opcode '%s', action '%s', table '%s'", rule.opcode_exact, rule.query_action_exact, regex_str)
	parts := strings.Split(path, "/")
	if rule.opcode_exact != "" && rule.opcode_exact != parts[1] {
		log.Infof("CassandraRule: opcode mismatch %v, %s", rule.opcode_exact, parts[0])
		return false
	}
	if rule.opcode_exact != "query" {
		log.Infof("CassandraRule: opcode-only match suceeded")
		return true
	}
	if rule.query_action_exact != "" && rule.query_action_exact != parts[2] {
		log.Infof("CassandraRule: query_action mismatch %v, %s", rule.query_action_exact, parts[1])
		return false
	}
	if rule.table_regex_compiled != nil && !rule.table_regex_compiled.MatchString(parts[3]) {
		log.Infof("CassandraRule: table_regex mismatch '%v', '%s'", rule.table_regex_compiled, parts[3])
		return false
	}

	return true
}

// L7HeaderRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func CassandraRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		panic(fmt.Errorf("Can't get L7 rules."))
	}
	var rules []L7NetworkPolicyRule
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var cr CassandraRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "opcode":
				cr.opcode_exact = v
			case "query_action":
				cr.query_action_exact = v
			case "query_table":
				if v != "" {
					cr.table_regex_compiled = regexp.MustCompile(v)
				}
			default:
				panic(fmt.Errorf("Unsupported key: %s", k))
			}
		}
		log.Infof("Parsed CassandraRule pair: %v", cr)
		rules = append(rules, &cr)
	}
	return rules
}

type CassandraParserFactory struct{}

var cassandraParserFactory *CassandraParserFactory

func init() {
	log.Info("init(): Registering cassandraParserFactory")
	RegisterParserFactory("cassandra", cassandraParserFactory)
	RegisterL7RuleParser("cassandra", CassandraRuleParser)
}

type CassandraParser struct {
	connection *Connection
	inserted   bool
	keyspace   string // stores current keyspace name from 'use' command

	// stores prepared query string while
	// waiting for 'prepared' reply from server
	// with a prepared id.
	// replies associated via stream-id
	preparedQueryPathByStreamId map[uint16]string

	// allowing us to enforce policy on query
	// at the time of the execute command.
	preparedQueryPathByPreparedId map[string]string // stores query string based on prepared-id,
}

func (pf *CassandraParserFactory) Create(connection *Connection) Parser {
	log.Infof("CassandraParserFactory: Create: %v", connection)

	p := CassandraParser{connection: connection}
	p.preparedQueryPathByStreamId = make(map[uint16]string)
	p.preparedQueryPathByPreparedId = make(map[string]string)
	return &p
}

func (p *CassandraParser) OnData(reply, endStream bool, data_arr [][]byte, offset int) (OpType, int) {

	// inefficient, but simple for now
	data := bytes.Join(data_arr, []byte(""))[offset:]
	log.Infof("OnData offset  = %d", offset)

	hdr_missing := 9 - len(data)
	if hdr_missing > 0 {
		// Partial header received, ask for more

		log.Infof("Did not receive full header, need %d more bytes", hdr_missing)
		return MORE, hdr_missing
	}

	// full header available, read full request length
	request_len := binary.BigEndian.Uint32(data[5:9])
	log.Infof("Request length = %d", request_len)

	data_missing := (9 + int(request_len)) - len(data)
	if data_missing > 0 {
		// full header received, but only partial request

		log.Infof("Hdr received, but need %d more bytes of request", data_missing)
		return MORE, data_missing
	}

	// we don't parse reply traffic for now
	if reply {
		if len(data) == 0 {
			log.Infof("ignoring zero length reply call to onData")
			return NOP, 0

		}
		cassandra_parse_reply(p, data[0:(9+request_len)])

		log.Infof("reply, passing %d bytes", uint32(len(data)))
		return PASS, len(data)
	}

	err, paths := cassandra_parse_request(p, data[0:(9+request_len)])
	if err != 0 {
		log.Infof("print parsing error %d", err)
		return ERROR, 0
	}

	log.Infof("Request paths = %s", paths)

	matches := true
	access_log_entry_type := cilium.EntryType_Request

	for i := 0; i < len(paths); i++ {
		if !p.connection.Matches(paths[i]) {
			matches = false
			access_log_entry_type = cilium.EntryType_Denied
		}
	}

	for i := 0; i < len(paths); i++ {
		parts := strings.Split(paths[i], "/")
		if len(parts) == 2 {
			p.connection.Log(access_log_entry_type,
				&cilium.LogEntry_GenericL7{
					&cilium.L7LogEntry{
						Proto: "cassandra",
						Fields: map[string]string{
							"opcode": parts[1],
						},
					},
				})
		} else if len(parts) == 4 {
			p.connection.Log(access_log_entry_type,
				&cilium.LogEntry_GenericL7{
					&cilium.L7LogEntry{
						Proto: "cassandra",
						Fields: map[string]string{
							"opcode":       parts[1],
							"query_action": parts[2],
							"query_table":  parts[3],
						},
					},
				})
		}
	}

	if matches {
		return PASS, int(request_len + 9)
	} else {

		unauth_msg := make([]byte, len(unauth_msg_base))
		copy(unauth_msg, unauth_msg_base)
		// We want to use the same protocol and stream ID
		// as the incoming request.
		// update the protocol to match the request
		unauth_msg[0] = 0x80 | (data[0] & 0x07)
		// update the stream ID to match the request
		unauth_msg[2] = data[2]
		unauth_msg[3] = data[3]
		p.connection.Inject(true, unauth_msg)

		return DROP, int(request_len + 9)
	}

}

// A full response (header + body) to be used as an
// "unauthorized" error to be sent to cassandra client as part of policy
// deny.   Array must be updated to ensure that reply has
// protocol version and stream-id that matches the request.

var unauth_msg_base = []byte{
	0x0,      // version (uint8) - must be set before injection
	0x0,      // flags, (uint8)
	0x0, 0x0, // stream-id (uint16) - must be set before injection
	0x0,                 // opcode error (uint8)
	0x0, 0x0, 0x0, 0x1a, // request length (uint32) - update if text changes
	0x0, 0x0, 0x21, 0x00, // 'unauthorized error code' 0x2100 (uint32)
	0x0, 0x14, // length of error msg (uint16)  - update if text changes
	'R', 'e', 'q', 'u', 'e', 's', 't', ' ', 'U', 'n', 'a', 'u', 't', 'h', 'o', 'r', 'i', 'z', 'e', 'd',
}

// A full response (header + body) to be used as a
// "unprepared" error to be sent to cassandra client if proxy
// does not have the path for this prepare-query-id cached

var unprepared_msg_base = []byte{
	0x0,      // version (uint8) - must be set before injection
	0x0,      // flags, (uint8)
	0x0, 0x0, // stream-id (uint16) - must be set before injection
	0x0,                 // opcode error (uint8)
	0x0, 0x0, 0x0, 0x1a, // request length (uint32) - update if text changes
	0x0, 0x0, 0x25, 0x00, // 'unauthorized error code' 0x2100 (uint32)
	// must append [short bytes] array of prepared query id.
}

var opcodeMap = map[byte]string{
	0x00: "error",
	0x01: "startup",
	0x02: "ready",
	0x03: "authenticate",
	0x05: "options",
	0x06: "supported",
	0x07: "query",
	0x08: "result",
	0x09: "prepare",
	0x0A: "execute",
	0x0B: "register",
	0x0C: "event",
	0x0D: "batch",
	0x0E: "auth_challenge",
	0x0F: "auth_response",
	0x10: "auth_success",
}

var reg_select = regexp.MustCompile("(?i)^select ")
var reg_insert = regexp.MustCompile("(?i)^insert ")
var reg_update = regexp.MustCompile("(?i)^update ")
var reg_delete = regexp.MustCompile("(?i)^delete ")
var reg_use = regexp.MustCompile("(?i)^use ")
var reg_from = regexp.MustCompile("(?i)^from$")

func parse_query(p *CassandraParser, query string) (string, string) {
	var action string
	var table string = ""
	if reg_select.MatchString(query) {
		action = "select"
		fields := strings.Fields(query)
		for i := 0; i < len(fields); i++ {
			if reg_from.MatchString(fields[i]) {
				table = strings.ToLower(fields[i+1])
			}
		}
		if len(table) == 0 {
			log.Warnf("Unable to parse table name from select query '%s'", query)
		}
	} else if reg_insert.MatchString(query) {
		action = "insert"
		fields := strings.Fields(query)
		table = strings.ToLower(fields[2])
	} else if reg_update.MatchString(query) {
		action = "update"
		fields := strings.Fields(query)
		table = strings.ToLower(fields[2])
	} else if reg_delete.MatchString(query) {
		action = "delete"
		fields := strings.Fields(query)
		for i := 0; i < len(fields); i++ {
			if reg_from.MatchString(fields[i]) {
				table = strings.ToLower(fields[i+1])
			}
		}
		if len(table) == 0 {
			log.Warnf("Unable to parse table name from delete query '%s'", query)
		}
	} else if reg_use.MatchString(query) {
		action = "use"
		p.keyspace = strings.Trim(strings.Fields(query)[1], "\"\\'")
		log.Infof("Saving keyspace '%s'", p.keyspace)
		table = "*"
	} else {
		fields := strings.Fields(strings.ToLower(query))
		f0 := fields[0]
		if strings.Compare(f0, "alter") == 0 ||
			strings.Compare(f0, "drop") == 0 ||
			strings.Compare(f0, "create") == 0 ||
			strings.Compare(f0, "list") == 0 {
			action = strings.Join([]string{f0, fields[1]}, "-")
		} else {
			action = f0
		}
	}
	if len(table) > 0 && !strings.Contains(table, ".") {
		table = p.keyspace + "." + table
	}
	return action, table
}

func cassandra_parse_request(p *CassandraParser, data []byte) (OpError, []string) {

	direction := data[0] & 0x80 // top bit
	if direction != 0 {
		log.Errorf("Direction bit is 'reply', but we are trying to parse a request")
		return ERROR_INVALID_FRAME_TYPE, nil
	}

	compression_flag := data[1] & 0x01
	if compression_flag == 1 {
		log.Errorf("Compression flag set, unable to parse beyond the header")
		return ERROR_INVALID_FRAME_TYPE, nil
	}

	opcode := data[4]
	path := opcodeMap[opcode]

	// parse query string from query/prepare/batch requests

	// NOTE: parsing only prepare statements and passing all execute
	// statements requires that we 'invalidate' all execute statements
	// anytime policy changes, to ensure that no execute statements are
	// allowed that correspond to prepared queries that would no longer
	// be valid.   A better option might be to cache all prepared queries,
	// mapping the execution ID to allow/deny each time policy is changed.
	if opcode == 0x07 || opcode == 0x09 {
		// query || prepare
		query_len := binary.BigEndian.Uint32(data[9:13])
		end_index := 13 + query_len
		query := string(data[13:end_index])
		action, table := parse_query(p, query)

		path = "/" + path + "/" + action + "/" + table
		if opcode == 0x09 {
			// stash 'path' for this prepared query based on stream id
			// rewrite 'opcode' portion of the path to be 'execute' rather than 'prepare'
			streamId := binary.BigEndian.Uint16(data[2:4])
			log.Infof("Prepare query path '%s' with stream-id %d", path, streamId)
			p.preparedQueryPathByStreamId[streamId] = strings.Replace(path, "prepare", "execute", 1)
		}
		return 0, []string{path}
	} else if opcode == 0x0d {
		// batch

		// TODO: need to handle already prepared query in batch requests

		num_queries := binary.BigEndian.Uint16(data[10:11])
		paths := make([]string, num_queries)
		log.Infof("batch query count = %d", num_queries)
		offset := 11
		for i := 0; i < int(num_queries); i++ {
			query_len := binary.BigEndian.Uint32(data[offset : offset+4])
			query_end_offset := offset + 4 + int(query_len)
			query := string(data[offset+4 : query_end_offset])

			action, table := parse_query(p, query)
			path = "/" + path + "/" + action + "/" + table
			paths[i] = path
			offset = query_end_offset
		}
		return 0, paths
	} else if opcode == 0x0a {
		// execute

		// parse out prepared query id, and then look up our
		// cached query path for policy evaluation.
		idLen := binary.BigEndian.Uint16(data[9:11])
		preparedId := string(data[11:(11 + idLen)])
		log.Infof("Execute with prepared-id = '%s'", preparedId)
		path := p.preparedQueryPathByPreparedId[preparedId]
		if len(path) > 0 {
			return 0, []string{path}
		} else {
			log.Warnf("No cached entry for prepared-id = '%s'", preparedId)
			//TODO: return error with error code 'unprepared' with code 0x2500
			// followed by a [short bytes] indicating the unknown ID
			// must set stream-id of the response to match the request

			unprepared_msg := make([]byte, len(unprepared_msg_base))
			copy(unprepared_msg, unprepared_msg_base)
			// We want to use the same protocol and stream ID
			// as the incoming request.
			// update the protocol to match the request
			unprepared_msg[0] = 0x80 | (data[0] & 0x07)
			// update the stream ID to match the request
			unprepared_msg[2] = data[2]
			unprepared_msg[3] = data[3]
			p.connection.Inject(true, unprepared_msg)
			// finish error message with a copy of the prepared-query-id
			// in [short bytes] format
			p.connection.Inject(true, data[9:11+idLen])

			return ERROR_INVALID_FRAME_TYPE, nil
		}
	} else {
		// other opcode, just return type of opcode

		return 0, []string{"/" + path}
	}

}

// reply parsing is very basic, just focusing on parsing RESULT messages that
// contain prepared query IDs so that we can later enforce policy on "execute" requests.
func cassandra_parse_reply(p *CassandraParser, data []byte) {

	direction := data[0] & 0x80 // top bit
	if direction != 0x80 {
		log.Errorf("Direction bit is 'request', but we are trying to parse a reply")
		return
	}

	compression_flag := data[1] & 0x01
	if compression_flag == 1 {
		log.Errorf("Compression flag set, unable to parse beyond the header")
		return
	}

	streamId := binary.BigEndian.Uint16(data[2:4])
	log.Infof("Reply with opcode %d and stream-id %d", data[4], streamId)
	// if this is an opcode == RESULT message of type 'prepared', associate the prepared
	// statement id with the full query string that was included in the
	// associated PREPARE request.  The stream-id in this reply allows us to
	// find the associated prepare query string.
	if data[4] == 0x08 {
		resultKind := binary.BigEndian.Uint32(data[9:13])
		log.Infof("resultKind = %d", resultKind)
		if resultKind == 0x0004 {
			idLen := binary.BigEndian.Uint16(data[13:15])
			preparedId := string(data[15 : 15+idLen])
			log.Infof("Result with prepared-id = '%s' for stream-id %d", preparedId, streamId)
			path := p.preparedQueryPathByStreamId[streamId]
			if len(path) > 0 {
				// found cached query path to associate with this preparedId
				p.preparedQueryPathByPreparedId[preparedId] = path
				log.Infof("Associating query path '%s' with prepared-id %d as part of stream-id %d", path, preparedId, streamId)
			} else {
				log.Warnf("Unable to find prepared query path associated with stream-id %d", streamId)
			}
		}
	}
}

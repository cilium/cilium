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

// Current Cassandra parser supports filtering on messages where the opcode is 'query-like'
// (i.e., opcode 'query', 'prepare', 'batch'.  In those scenarios, we match on query_action and query_table.
// Examples:
// query_action = 'select', query_table = 'system.*'
// query_action = 'insert', query_table = 'attendance.daily_records'
// query_action = 'select', query_table = 'deathstar.scrum_notes'
// query_action = 'insert', query_table = 'covalent.foo'
//
// Batch requests are logged as invidual queries, but an entire batch request will be allowed
// only if all requests are allowed.

// There are known changes in protocol v2 that are not compatible with this parser, see the
// the "Changes from v2" in https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v3.spec

type CassandraRule struct {
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

	log.Infof("Rule: action '%s', table '%s'", rule.query_action_exact, regex_str)
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		// this is not a query-like request
		// just allow
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
			case "query_action":
				cr.query_action_exact = v
			case "query_table":
				if v != "" {
					// TODO:  better handling for invalid regex?
					cr.table_regex_compiled = regexp.MustCompile(v)
				}
			default:
				panic(fmt.Errorf("Unsupported key: %s", k))
			}
		}
		if len(cr.query_action_exact) > 0 {
			// ensure this is a valid query action
			res := queryActionMap[cr.query_action_exact]
			if res == 0 {
				log.Warnf("Unable to parse L7 cassandra rule with invalid query_action: '%s'", cr.query_action_exact)
				continue
			} else if res == 2 && cr.table_regex_compiled != nil {
				log.Warnf("query_action '%s' is not compatible with a query_table match", cr.query_action_exact)
				continue
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
		cassandraParseReply(p, data[0:(9+request_len)])

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
		if len(parts) == 4 {
			p.connection.Log(access_log_entry_type,
				&cilium.LogEntry_GenericL7{
					&cilium.L7LogEntry{
						Proto: "cassandra",
						Fields: map[string]string{
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

// map to test whether a 'query_action' is valid or not
// 1 - indicates a query_action that accepts a query_table policy match
// 2 - indicates a query_action that does not accept a query_table policy match
var queryActionMap = map[string]int{
	"select":         1,
	"delete":         1,
	"insert":         1,
	"update":         1,
	"create-table":   1,
	"drop-table":     1,
	"alter-table":    1,
	"truncate-table": 1,

	// these queries take a keyspace
	// and match against query_table
	"use":             1,
	"create-keyspace": 1,
	"alter-keyspace":  1,
	"drop-keyspace":   1,

	"drop-index":               2,
	"create-index":             2, // TODO: we could tie this to table if we want
	"create-materialized-view": 2,
	"drop-materialized-view":   2,

	// TODO: these admin ops could be bundled into meta roles
	// (e.g., role-mgmt, permission-mgmt)
	"create-role":       2,
	"alter-role":        2,
	"drop-role":         2,
	"grant-role":        2,
	"revoke-role":       2,
	"list-roles":        2,
	"grant-permission":  2,
	"revoke-permission": 2,
	"list-permissions":  2,
	"create-user":       2,
	"alter-user":        2,
	"drop-user":         2,
	"list-users":        2,

	"create-function":  2,
	"drop-function":    2,
	"create-aggregate": 2,
	"drop-aggregate":   2,
	"create-type":      2,
	"alter-type":       2,
	"drop-type":        2,
	"create-trigger":   2,
	"drop-trigger":     2,
}

func parse_query(p *CassandraParser, query string) (string, string) {
	var action string
	var table string = ""

	query = strings.TrimRight(query, ";")            // remove potential trailing ;
	fields := strings.Fields(strings.ToLower(query)) // handles all whitespace

	// we currently do not strip comments.  It seems like cqlsh does
	// strip comments, but its not clear if that can be assumed of all clients
	// It should not be possible to "spoof" the 'action' as this is assumed to be
	// the first token (leaving no room for a comment to start), but it could potentially
	// trick this parser into thinking we're accessing table X, when in fact the
	// query accesses table Y, which would obviously be a security vulnerability
	// As a result, we look at each token here, and if any of them match the comment
	// characters for cassandra, we fail parsing.
	for i := 0; i < len(fields); i++ {
		if len(fields[i]) >= 2 &&
			(fields[i][:2] == "--" ||
				fields[i][:2] == "/*" ||
				fields[i][:2] == "//") {

			log.Warnf("Unable to safely parse query with comments '%s'", query)
			return "", ""
		}
	}

	action = fields[0]
	if action == "select" || action == "delete" {
		for i := 1; i < len(fields); i++ {
			if fields[i] == "from" {
				table = strings.ToLower(fields[i+1])
			}
		}
		if len(table) == 0 {
			log.Warnf("Unable to parse table name from query '%s'", query)
			return "", ""
		}
	} else if action == "insert" {
		// INSERT into <table-name>
		table = strings.ToLower(fields[2])
	} else if action == "update" {
		// UPDATE <table-name>
		table = strings.ToLower(fields[1])
	} else if action == "use" {
		p.keyspace = strings.Trim(fields[1], "\"\\'")
		log.Infof("Saving keyspace '%s'", p.keyspace)
		table = p.keyspace
	} else if action == "alter" ||
		action == "create" ||
		action == "drop" ||
		action == "truncate" ||
		action == "list" {

		action = strings.Join([]string{action, fields[1]}, "-")
		if fields[1] == "table" || fields[1] == "keyspace" {
			table = fields[2]
			if table == "if" {
				if action == "create-table" {
					// handle optional "IF NOT EXISTS"
					table = fields[5]
				} else if action == "drop-table" || action == "drop-keyspace" {
					// handle optional "IF EXISTS"
					table = fields[4]
				}
			}
		}
		if action == "truncate" && len(fields) == 2 {
			// special case, truncate can just be passed table name
			table = fields[1]
		}
		if fields[1] == "materialized" {
			action = action + "-view"
		} else if fields[1] == "custom" {
			action = "create-index"
		}
	} else {
		log.Errorf("Unexpected action '%s', unable to parse query", action)
		return "", ""
	}

	if len(table) > 0 && !strings.Contains(table, ".") && action != "use" {
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

	compressionFlag := data[1] & 0x01
	if compressionFlag == 1 {
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
		queryLen := binary.BigEndian.Uint32(data[9:13])
		endIndex := 13 + queryLen
		query := string(data[13:endIndex])
		action, table := parse_query(p, query)

		if action == "" {
			return ERROR_INVALID_FRAME_TYPE, nil
		}

		path = "/" + path + "/" + action + "/" + table
		if opcode == 0x09 {
			// stash 'path' for this prepared query based on stream id
			// rewrite 'opcode' portion of the path to be 'execute' rather than 'prepare'
			streamID := binary.BigEndian.Uint16(data[2:4])
			log.Infof("Prepare query path '%s' with stream-id %d", path, streamID)
			p.preparedQueryPathByStreamId[streamID] = strings.Replace(path, "prepare", "execute", 1)
		}
		return 0, []string{path}
	} else if opcode == 0x0d {
		// batch

		// TODO: need to handle prepared queries in batch requests

		num_queries := binary.BigEndian.Uint16(data[10:11])
		paths := make([]string, num_queries)
		log.Infof("batch query count = %d", num_queries)
		offset := 11
		for i := 0; i < int(num_queries); i++ {
			kind := data[offset]
			if kind == 0 {
				// full query string
				query_len := int(binary.BigEndian.Uint32(data[offset : offset+4]))

				query := string(data[offset+4 : offset+4+query_len])
				action, table := parse_query(p, query)

				if action == "" {
					return ERROR_INVALID_FRAME_TYPE, nil
				}
				path = "/" + path + "/" + action + "/" + table
				paths[i] = path
				offset = offset + 5 + query_len
			} else if kind == 1 {
				// prepared query id
				idLen := int(binary.BigEndian.Uint32(data[offset+1 : offset+3]))
				preparedId := string(data[offset+3 : (offset + 3 + idLen)])
				log.Infof("Batch entry with prepared-id = '%s'", preparedId)
				path := p.preparedQueryPathByPreparedId[preparedId]
				if len(path) > 0 {
					paths[i] = path
				} else {
					log.Warnf("No cached entry for prepared-id = '%s' in batch", preparedId)
					send_unprepared_msg(p, data[0], data[2:4], data[9:11+idLen])
					return ERROR_INVALID_FRAME_TYPE, nil
				}
				offset = offset + 3 + idLen
			} else {
				log.Errorf("unexpected value of 'kind' in batch query: %d", kind)
				return ERROR_INVALID_FRAME_TYPE, nil
			}
		}
		return 0, paths
	} else if opcode == 0x0a {
		// execute

		// parse out prepared query id, and then look up our
		// cached query path for policy evaluation.
		idLen := binary.BigEndian.Uint16(data[9:11])
		preparedID := string(data[11:(11 + idLen)])
		log.Infof("Execute with prepared-id = '%s'", preparedID)
		path := p.preparedQueryPathByPreparedId[preparedID]
		if len(path) > 0 {
			return 0, []string{path}
		} else {
			log.Warnf("No cached entry for prepared-id = '%s'", preparedID)
			send_unprepared_msg(p, data[0], data[2:4], data[9:11+idLen])
			return ERROR_INVALID_FRAME_TYPE, nil
		}
	} else {
		// other opcode, just return type of opcode

		return 0, []string{"/" + path}
	}

}

// return error with error code 'unprepared' with code 0x2500
// followed by a [short bytes] indicating the unknown ID
// must set stream-id of the response to match the request
func send_unprepared_msg(p *CassandraParser, version byte, streamID []byte, preparedId []byte) {

	unprepared_msg := make([]byte, len(unprepared_msg_base))
	copy(unprepared_msg, unprepared_msg_base)
	// We want to use the same protocol and stream ID
	// as the incoming request.
	// update the protocol version to match the request
	unprepared_msg[0] = 0x80 | (version & 0x07)
	// update the stream ID to match the request
	unprepared_msg[2] = streamID[0]
	unprepared_msg[3] = streamID[1]
	p.connection.Inject(true, unprepared_msg)
	// finish error message with a copy of the prepared-query-id
	// in [short bytes] format
	p.connection.Inject(true, preparedId)
}

// reply parsing is very basic, just focusing on parsing RESULT messages that
// contain prepared query IDs so that we can later enforce policy on "execute" requests.
func cassandraParseReply(p *CassandraParser, data []byte) {

	direction := data[0] & 0x80 // top bit
	if direction != 0x80 {
		log.Errorf("Direction bit is 'request', but we are trying to parse a reply")
		return
	}

	compressionFlag := data[1] & 0x01
	if compressionFlag == 1 {
		log.Errorf("Compression flag set, unable to parse beyond the header")
		return
	}

	streamID := binary.BigEndian.Uint16(data[2:4])
	log.Infof("Reply with opcode %d and stream-id %d", data[4], streamID)
	// if this is an opcode == RESULT message of type 'prepared', associate the prepared
	// statement id with the full query string that was included in the
	// associated PREPARE request.  The stream-id in this reply allows us to
	// find the associated prepare query string.
	if data[4] == 0x08 {
		resultKind := binary.BigEndian.Uint32(data[9:13])
		log.Infof("resultKind = %d", resultKind)
		if resultKind == 0x0004 {
			idLen := binary.BigEndian.Uint16(data[13:15])
			preparedID := string(data[15 : 15+idLen])
			log.Infof("Result with prepared-id = '%s' for stream-id %d", preparedID, streamID)
			path := p.preparedQueryPathByStreamId[streamID]
			if len(path) > 0 {
				// found cached query path to associate with this preparedID
				p.preparedQueryPathByPreparedId[preparedID] = path
				log.Infof("Associating query path '%s' with prepared-id %s as part of stream-id %d", path, preparedID, streamID)
			} else {
				log.Warnf("Unable to find prepared query path associated with stream-id %d", streamID)
			}
		}
	}
}

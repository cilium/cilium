// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cassandra

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"

	. "github.com/cilium/cilium/proxylib/proxylib"
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

// Non-query client requests, including 'Options', 'Auth_Response', 'Startup', and 'Register'
// are automatically allowed to simplify the policy language.

// There are known changes in protocol v2 that are not compatible with this parser, see the
// the "Changes from v2" in https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v3.spec

type CassandraRule struct {
	queryActionExact   string
	tableRegexCompiled *regexp.Regexp
}

const cassHdrLen = 9
const cassMaxLen = 268435456 // 256 MB, per spec

const unknownPreparedQueryPath = "/unknown-prepared-query"

func (rule *CassandraRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	path, ok := data.(string)
	if !ok {
		logrus.Warning("Matches() called with type other than string")
		return false
	}
	logrus.Debugf("Policy Match test for '%s'", path)
	regexStr := ""
	if rule.tableRegexCompiled != nil {
		regexStr = rule.tableRegexCompiled.String()
	}

	logrus.Debugf("Rule: action '%s', table '%s'", rule.queryActionExact, regexStr)
	if path == unknownPreparedQueryPath {
		logrus.Warning("Dropping execute for unknown prepared-id")
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		// this is not a query-like request, just allow
		return true
	} else if len(parts) < 4 {
		// should never happen unless we've messed up internally
		// as path is either /<opcode> or /<opcode>/<action>/<table>
		logrus.Errorf("Invalid parsed path: '%s'", path)
		return false
	}
	if rule.queryActionExact != "" && rule.queryActionExact != parts[2] {
		logrus.Debugf("CassandraRule: query_action mismatch %v, %s", rule.queryActionExact, parts[1])
		return false
	}
	if len(parts[3]) > 0 &&
		rule.tableRegexCompiled != nil &&
		!rule.tableRegexCompiled.MatchString(parts[3]) {
		logrus.Debugf("CassandraRule: table_regex mismatch '%v', '%s'", rule.tableRegexCompiled, parts[3])
		return false
	}

	return true
}

// CassandraRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func CassandraRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return nil
	}

	allowRules := l7Rules.GetL7AllowRules()
	rules := make([]L7NetworkPolicyRule, 0, len(allowRules))
	for _, l7Rule := range allowRules {
		var cr CassandraRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "query_action":
				cr.queryActionExact = v
			case "query_table":
				if v != "" {
					cr.tableRegexCompiled = regexp.MustCompile(v)
				}
			default:
				ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if len(cr.queryActionExact) > 0 {
			// ensure this is a valid query action
			res := queryActionMap[cr.queryActionExact]
			if res == invalidAction {
				ParseError(fmt.Sprintf("Unable to parse L7 cassandra rule with invalid query_action: '%s'", cr.queryActionExact), rule)
			} else if res == actionNoTable && cr.tableRegexCompiled != nil {
				ParseError(fmt.Sprintf("query_action '%s' is not compatible with a query_table match", cr.queryActionExact), rule)
			}

		}

		logrus.Debugf("Parsed CassandraRule pair: %v", cr)
		rules = append(rules, &cr)
	}
	return rules
}

type CassandraParserFactory struct{}

var cassandraParserFactory *CassandraParserFactory

func init() {
	logrus.Debug("init(): Registering cassandraParserFactory")
	RegisterParserFactory("cassandra", cassandraParserFactory)
	RegisterL7RuleParser("cassandra", CassandraRuleParser)
}

type CassandraParser struct {
	connection *Connection
	keyspace   string // stores current keyspace name from 'use' command

	// stores prepared query string while
	// waiting for 'prepared' reply from server
	// with a prepared id.
	// replies associated via stream-id
	preparedQueryPathByStreamID map[uint16]string

	// allowing us to enforce policy on query
	// at the time of the execute command.
	preparedQueryPathByPreparedID map[string]string // stores query string based on prepared-id,
}

func (pf *CassandraParserFactory) Create(connection *Connection) interface{} {
	logrus.Debugf("CassandraParserFactory: Create: %v", connection)

	p := CassandraParser{connection: connection}
	p.preparedQueryPathByStreamID = make(map[uint16]string)
	p.preparedQueryPathByPreparedID = make(map[string]string)
	return &p
}

func (p *CassandraParser) OnData(reply, endStream bool, dataArray [][]byte) (OpType, int) {

	// inefficient, but simple for now
	data := bytes.Join(dataArray, []byte{})

	if len(data) < cassHdrLen {
		// Partial header received, ask for more
		needs := cassHdrLen - len(data)
		logrus.Debugf("Did not receive full header, need %d more bytes", needs)
		return MORE, needs
	}

	// full header available, read full request length
	requestLen := binary.BigEndian.Uint32(data[5:9])
	logrus.Debugf("Request length = %d", requestLen)
	if requestLen > cassMaxLen {
		logrus.Errorf("Request length of %d is greater than 256 MB", requestLen)
		return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
	}

	dataMissing := (cassHdrLen + int(requestLen)) - len(data)
	if dataMissing > 0 {
		// full header received, but only partial request

		logrus.Debugf("Hdr received, but need %d more bytes of request", dataMissing)
		return MORE, dataMissing
	}

	// we parse replies, but only to look for prepared-query-id responses
	if reply {
		if len(data) == 0 {
			logrus.Debugf("ignoring zero length reply call to onData")
			return NOP, 0

		}
		cassandraParseReply(p, data[0:(cassHdrLen+requestLen)])

		logrus.Debugf("reply, passing %d bytes", (cassHdrLen + requestLen))
		return PASS, (cassHdrLen + int(requestLen))
	}

	err, paths := cassandraParseRequest(p, data[0:(cassHdrLen+requestLen)])
	if err != 0 {
		logrus.Errorf("Parsing error %d", err)
		return ERROR, int(err)
	}

	logrus.Debugf("Request paths = %s", paths)

	matches := true
	access_log_entry_type := cilium.EntryType_Request
	unpreparedQuery := false

	for i := 0; i < len(paths); i++ {
		if strings.HasPrefix(paths[i], "/query/use/") ||
			strings.HasPrefix(paths[i], "/batch/use/") ||
			strings.HasPrefix(paths[i], "/prepare/use/") {
			// do not count a "use" query as a deny
			continue
		}

		if paths[i] == unknownPreparedQueryPath {
			matches = false
			unpreparedQuery = true
			access_log_entry_type = cilium.EntryType_Denied
			break
		}

		if !p.connection.Matches(paths[i]) {
			matches = false
			access_log_entry_type = cilium.EntryType_Denied
			break
		}
	}

	for i := 0; i < len(paths); i++ {
		parts := strings.Split(paths[i], "/")
		fields := map[string]string{}

		if len(parts) >= 3 && parts[2] == "use" {
			// do not log 'use' queries
			continue
		} else if len(parts) == 4 {
			fields["query_action"] = parts[2]
			fields["query_table"] = parts[3]
		} else if unpreparedQuery {
			fields["error"] = "unknown prepared query id"
		} else {
			// do not log non-query accesses
			continue
		}

		p.connection.Log(access_log_entry_type,
			&cilium.LogEntry_GenericL7{
				GenericL7: &cilium.L7LogEntry{
					Proto:  "cassandra",
					Fields: fields,
				},
			})

	}

	if !matches {

		// If we have already sent another error to the client,
		// do not send unauthorized message
		if !unpreparedQuery {
			unauthMsg := make([]byte, len(unauthMsgBase))
			copy(unauthMsg, unauthMsgBase)
			// We want to use the same protocol and stream ID
			// as the incoming request.
			// update the protocol to match the request
			unauthMsg[0] = 0x80 | (data[0] & 0x07)
			// update the stream ID to match the request
			unauthMsg[2] = data[2]
			unauthMsg[3] = data[3]
			p.connection.Inject(true, unauthMsg)
		}
		return DROP, int(cassHdrLen + requestLen)
	}

	return PASS, int(cassHdrLen + requestLen)
}

// A full response (header + body) to be used as an
// "unauthorized" error to be sent to cassandra client as part of policy
// deny.   Array must be updated to ensure that reply has
// protocol version and stream-id that matches the request.

var unauthMsgBase = []byte{
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

var unpreparedMsgBase = []byte{
	0x0,      // version (uint8) - must be set before injection
	0x0,      // flags, (uint8)
	0x0, 0x0, // stream-id (uint16) - must be set before injection
	0x0,                // opcode error (uint8)
	0x0, 0x0, 0x0, 0x0, // request length (uint32) - must be set based on
	// of length of prepared query id
	0x0, 0x0, 0x25, 0x00, // 'unprepared error code' 0x2500 (uint32)
	// must append [short bytes] array of prepared query id.
}

// create reply byte buffer with error code 'unprepared' with code 0x2500
// followed by a [short bytes] indicating the unknown ID
// must set stream-id of the response to match the request
func createUnpreparedMsg(version byte, streamID []byte, preparedID string) []byte {

	unpreparedMsg := make([]byte, len(unpreparedMsgBase))
	copy(unpreparedMsg, unpreparedMsgBase)
	unpreparedMsg[0] = 0x80 | version
	unpreparedMsg[2] = streamID[0]
	unpreparedMsg[3] = streamID[1]

	idLen := len(preparedID)
	idLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(idLenBytes, uint16(idLen))

	reqLen := 4 + 2 + idLen
	reqLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(reqLenBytes, uint32(reqLen))
	unpreparedMsg[5] = reqLenBytes[0]
	unpreparedMsg[6] = reqLenBytes[1]
	unpreparedMsg[7] = reqLenBytes[2]
	unpreparedMsg[8] = reqLenBytes[3]

	res := append(unpreparedMsg, idLenBytes...)
	return append(res, []byte(preparedID)...)
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

const invalidAction = 0
const actionWithTable = 1
const actionNoTable = 2

var queryActionMap = map[string]int{
	"select":         actionWithTable,
	"delete":         actionWithTable,
	"insert":         actionWithTable,
	"update":         actionWithTable,
	"create-table":   actionWithTable,
	"drop-table":     actionWithTable,
	"alter-table":    actionWithTable,
	"truncate-table": actionWithTable,

	// these queries take a keyspace
	// and match against query_table
	"use":             actionWithTable,
	"create-keyspace": actionWithTable,
	"alter-keyspace":  actionWithTable,
	"drop-keyspace":   actionWithTable,

	"drop-index":               actionNoTable,
	"create-index":             actionNoTable, // TODO: we could tie this to table if we want
	"create-materialized-view": actionNoTable,
	"drop-materialized-view":   actionNoTable,

	// TODO: these admin ops could be bundled into meta roles
	// (e.g., role-mgmt, permission-mgmt)
	"create-role":       actionNoTable,
	"alter-role":        actionNoTable,
	"drop-role":         actionNoTable,
	"grant-role":        actionNoTable,
	"revoke-role":       actionNoTable,
	"list-roles":        actionNoTable,
	"grant-permission":  actionNoTable,
	"revoke-permission": actionNoTable,
	"list-permissions":  actionNoTable,
	"create-user":       actionNoTable,
	"alter-user":        actionNoTable,
	"drop-user":         actionNoTable,
	"list-users":        actionNoTable,

	"create-function":  actionNoTable,
	"drop-function":    actionNoTable,
	"create-aggregate": actionNoTable,
	"drop-aggregate":   actionNoTable,
	"create-type":      actionNoTable,
	"alter-type":       actionNoTable,
	"drop-type":        actionNoTable,
	"create-trigger":   actionNoTable,
	"drop-trigger":     actionNoTable,
}

func parseQuery(p *CassandraParser, query string) (string, string) {
	var action string
	var table string

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

			logrus.Warnf("Unable to safely parse query with comments '%s'", query)
			return "", ""
		}
	}
	if len(fields) < 2 {
		goto invalidQuery
	}

	action = fields[0]
	switch action {
	case "select", "delete":
		for i := 1; i < len(fields); i++ {
			if fields[i] == "from" {
				table = strings.ToLower(fields[i+1])
			}
		}
		if len(table) == 0 {
			logrus.Warnf("Unable to parse table name from query '%s'", query)
			return "", ""
		}
	case "insert":
		// INSERT into <table-name>
		if len(fields) < 3 {
			goto invalidQuery
		}
		table = strings.ToLower(fields[2])
	case "update":
		// UPDATE <table-name>
		table = strings.ToLower(fields[1])
	case "use":
		p.keyspace = strings.Trim(fields[1], "\"\\'")
		logrus.Debugf("Saving keyspace '%s'", p.keyspace)
		table = p.keyspace
	case "alter", "create", "drop", "truncate", "list":

		action = strings.Join([]string{action, fields[1]}, "-")
		if fields[1] == "table" || fields[1] == "keyspace" {

			if len(fields) < 3 {
				goto invalidQuery
			}
			table = fields[2]
			if table == "if" {
				if action == "create-table" {
					if len(fields) < 6 {
						goto invalidQuery
					}
					// handle optional "IF NOT EXISTS"
					table = fields[5]
				} else if action == "drop-table" || action == "drop-keyspace" {
					if len(fields) < 5 {
						goto invalidQuery
					}
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
	default:
		goto invalidQuery
	}

	if len(table) > 0 && !strings.Contains(table, ".") && action != "use" {
		table = p.keyspace + "." + table
	}
	return action, table

invalidQuery:

	logrus.Errorf("Unable to parse query: '%s'", query)
	return "", ""
}

func cassandraParseRequest(p *CassandraParser, data []byte) (OpError, []string) {

	direction := data[0] & 0x80 // top bit
	if direction != 0 {
		logrus.Errorf("Direction bit is 'reply', but we are trying to parse a request")
		return ERROR_INVALID_FRAME_TYPE, nil
	}

	compressionFlag := data[1] & 0x01
	if compressionFlag == 1 {
		logrus.Errorf("Compression flag set, unable to parse request beyond the header")
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
		action, table := parseQuery(p, query)

		if action == "" {
			return ERROR_INVALID_FRAME_TYPE, nil
		}

		path = "/" + path + "/" + action + "/" + table
		if opcode == 0x09 {
			// stash 'path' for this prepared query based on stream id
			// rewrite 'opcode' portion of the path to be 'execute' rather than 'prepare'
			streamID := binary.BigEndian.Uint16(data[2:4])
			logrus.Debugf("Prepare query path '%s' with stream-id %d", path, streamID)
			p.preparedQueryPathByStreamID[streamID] = strings.Replace(path, "prepare", "execute", 1)
		}
		return 0, []string{path}
	} else if opcode == 0x0d {
		// batch

		numQueries := binary.BigEndian.Uint16(data[10:12])
		paths := make([]string, numQueries)
		logrus.Debugf("batch query count = %d", numQueries)
		offset := 12
		for i := 0; i < int(numQueries); i++ {
			kind := data[offset]
			if kind == 0 {
				// full query string
				queryLen := int(binary.BigEndian.Uint32(data[offset+1 : offset+5]))

				query := string(data[offset+5 : offset+5+queryLen])
				action, table := parseQuery(p, query)

				if action == "" {
					return ERROR_INVALID_FRAME_TYPE, nil
				}
				path = "/" + path + "/" + action + "/" + table
				paths[i] = path
				path = "batch" // reset for next item
				offset = offset + 5 + queryLen
				offset = readPastBatchValues(data, offset)
			} else if kind == 1 {
				// prepared query id

				idLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
				preparedID := string(data[offset+3 : (offset + 3 + idLen)])
				logrus.Debugf("Batch entry with prepared-id = '%s'", preparedID)
				path := p.preparedQueryPathByPreparedID[preparedID]
				if len(path) > 0 {
					paths[i] = path
				} else {
					logrus.Warnf("No cached entry for prepared-id = '%s' in batch", preparedID)
					unpreparedMsg := createUnpreparedMsg(data[0], data[2:4], preparedID)
					p.connection.Inject(true, unpreparedMsg)
					return 0, []string{unknownPreparedQueryPath}
				}
				offset = offset + 3 + idLen

				offset = readPastBatchValues(data, offset)
			} else {
				logrus.Errorf("unexpected value of 'kind' in batch query: %d", kind)
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
		logrus.Debugf("Execute with prepared-id = '%s'", preparedID)
		path := p.preparedQueryPathByPreparedID[preparedID]

		if len(path) == 0 {
			logrus.Warnf("No cached entry for prepared-id = '%s'", preparedID)
			unpreparedMsg := createUnpreparedMsg(data[0], data[2:4], preparedID)
			p.connection.Inject(true, unpreparedMsg)

			// this path is special-cased in Matches() so that unknown
			// prepared IDs are dropped if any rules are defined
			return 0, []string{unknownPreparedQueryPath}
		}

		return 0, []string{path}
	} else {
		// other opcode, just return type of opcode

		return 0, []string{"/" + path}
	}

}

func readPastBatchValues(data []byte, initialOffset int) int {
	numValues := int(binary.BigEndian.Uint16(data[initialOffset : initialOffset+2]))
	offset := initialOffset + 2
	for i := 0; i < numValues; i++ {
		valueLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		// handle 'null' (-1) and 'not set' (-2) case, where 0 bytes follow
		if valueLen >= 0 {
			offset = offset + 4 + valueLen
		}
	}
	return offset
}

// reply parsing is very basic, just focusing on parsing RESULT messages that
// contain prepared query IDs so that we can later enforce policy on "execute" requests.
func cassandraParseReply(p *CassandraParser, data []byte) {

	direction := data[0] & 0x80 // top bit
	if direction != 0x80 {
		logrus.Errorf("Direction bit is 'request', but we are trying to parse a reply")
		return
	}

	compressionFlag := data[1] & 0x01
	if compressionFlag == 1 {
		logrus.Errorf("Compression flag set, unable to parse reply beyond the header")
		return
	}

	streamID := binary.BigEndian.Uint16(data[2:4])
	logrus.Debugf("Reply with opcode %d and stream-id %d", data[4], streamID)
	// if this is an opcode == RESULT message of type 'prepared', associate the prepared
	// statement id with the full query string that was included in the
	// associated PREPARE request.  The stream-id in this reply allows us to
	// find the associated prepare query string.
	if data[4] == 0x08 {
		resultKind := binary.BigEndian.Uint32(data[9:13])
		logrus.Debugf("resultKind = %d", resultKind)
		if resultKind == 0x0004 {
			idLen := binary.BigEndian.Uint16(data[13:15])
			preparedID := string(data[15 : 15+idLen])
			logrus.Debugf("Result with prepared-id = '%s' for stream-id %d", preparedID, streamID)
			path := p.preparedQueryPathByStreamID[streamID]
			if len(path) > 0 {
				// found cached query path to associate with this preparedID
				p.preparedQueryPathByPreparedID[preparedID] = path
				logrus.Debugf("Associating query path '%s' with prepared-id %s as part of stream-id %d", path, preparedID, streamID)
			} else {
				logrus.Warnf("Unable to find prepared query path associated with stream-id %d", streamID)
			}
		}
	}
}

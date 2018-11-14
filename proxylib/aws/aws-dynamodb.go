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

package awsparsers

import (
	"bytes"
	"encoding/json"
	"fmt"
	. "github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/proxy/go/cilium/api"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"regexp"
	"strings"
)

//
// AWS Dynamo DB Parser
//
// Spec:  https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Operations_Amazon_DynamoDB.html
//

// Current AWS DynamoDB parser supports matching on 'Action' and 'Table', both of which can be wildcarded.
// Table can be a regular expression.
// Examples:
// action = 'GetItem', table = 'table1'

type AWSDynamoDBRule struct {
	actionExact        string
	tableRegexCompiled *regexp.Regexp
}

type AWSDynamoDBRequestData struct {
	action string
	table  string
}

type AWSDynamoDBRequestJSON struct {
	TableName string
}

func (rule *AWSDynamoDBRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	reqData, ok := data.(AWSDynamoDBRequestData)
	if !ok {
		log.Warning("Matches() called with type other than string")
		return false
	}
	log.Infof("Match Request: action '%s' table '%s'", reqData.action, reqData.table)
	regexStr := ""
	if rule.tableRegexCompiled != nil {
		regexStr = rule.tableRegexCompiled.String()
	}
	log.Infof("Match Rule: action '%s', table '%s'", rule.actionExact, regexStr)

	if rule.actionExact != "" && rule.actionExact != reqData.action {
		log.Debugf("AWSDynamoDBRule: action mismatch %v, %s", rule.actionExact, reqData.action)
		return false
	}
	if len(reqData.table) > 0 &&
		rule.tableRegexCompiled != nil &&
		!rule.tableRegexCompiled.MatchString(reqData.table) {
		log.Debugf("AWSDynamoDBRule: table_regex mismatch '%s', '%s'", regexStr, reqData.table)
		return false
	}

	return true
}

// AWSDyanmoDBRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func AWSDynamoDBRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	var rules []L7NetworkPolicyRule
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return rules
	}
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var r AWSDynamoDBRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "action":
				r.actionExact = v
			case "table":
				if v != "" {
					r.tableRegexCompiled = regexp.MustCompile(v)
				}
			default:
				ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if len(r.actionExact) > 0 {
			// ensure this is a valid query action
			res := DynamoDBActionMap[r.actionExact]
			if res == invalidAction {
				ParseError(fmt.Sprintf("Unable to parse L7 AWS-DynamoDB rule with invalid action: '%s'", r.actionExact), rule)
			} else if res == actionNoTable && r.tableRegexCompiled != nil {
				ParseError(fmt.Sprintf("action '%s' is not compatible with a table match", r.actionExact), rule)
			}

		}

		log.Debugf("Parsed AWSDynamoDBRule pair: %v", r)
		rules = append(rules, &r)
	}
	return rules
}

type AWSDynamoDBParserFactory struct{}

var awsDynamoDBParserFactory *AWSDynamoDBParserFactory

func init() {
	log.Info("init(): Registering AWSDynamoDBParserFactory")
	RegisterParserFactory("aws-dynamodb", awsDynamoDBParserFactory)
	RegisterL7RuleParser("aws-dynamodb", AWSDynamoDBRuleParser)
}

type AWSDynamoDBParser struct {
	connection *Connection
	inserted   bool
}

func (pf *AWSDynamoDBParserFactory) Create(connection *Connection) Parser {
	log.Debugf("AWSDynamoDBParserFactory: Create: %v", connection)

	p := AWSDynamoDBParser{connection: connection}
	return &p
}

// see: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Programming.Errors.html
//  TODO: consider setting x-amzn-RequestID and Date headers, as customizing the version label.
var DynamoDBAccessDeniedStr string = "HTTP/1.1 403 Access Denied\r\n" +
	"Content-Type: application/x-amz-json-1.0\r\n" +
	"Content-Length: 118\r\n" +
	"\r\n" +
	`{"__type":"com.amazonaws.dynamodb.v20120810#AccessDeniedException","message":"Access Denied by Cilium Network Policy"}`

func (p *AWSDynamoDBParser) OnData(reply, endStream bool, dataArray [][]byte) (OpType, int) {

	// inefficient, but simple for now
	data := bytes.Join(dataArray, []byte{})

	log.Infof("OnData for DynamoDB parser with %d bytes, reply %v", len(data), reply)

	if reply {
		// do not parse replies
		// FIXME: will not work with pipelining
		//        Need to parse resonses, ensure we pass a full
		//        Response at a time.
		if len(data) > 0 {
			log.Infof("passing full reply of size %d", len(data))
			return PASS, len(data)
		} else {
			log.Infof("Reply with zero bytes of data")
			return MORE, 1
		}
	}

	req, reqLen, needs := parseHTTPRequest(data)
	if req == nil {
		if needs < 0 {
			log.Infof("Nil request: error")
			return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
		} else {
			log.Infof("Nil request: needs more")
			return MORE, needs
		}
	}
	log.Infof("Have full request with content-length: %d", req.ContentLength)

	targetHeader := req.Header.Get("X-Amz-Target")
	if len(targetHeader) == 0 || req.Body == nil {
		return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
	}
	targetSplitArr := strings.Split(targetHeader, ".")
	if len(targetSplitArr) != 2 {
		return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
	}
	action := targetSplitArr[1]
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Errorf("AWSDynamoDBParser:  Error reading Request Body")
		return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
	}
	var json_data AWSDynamoDBRequestJSON
	err = json.Unmarshal(body, &json_data)
	if err != nil {
		log.Errorf("AWSDynamoDBParser:  Error parsing Request Body as JSON")
		return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
	}

	// TODO: handle batch operations, and requests that modify global tables.

	log.Infof("table: %s  action: %s", json_data.TableName, action)

	reqData := AWSDynamoDBRequestData{action: action, table: json_data.TableName}

	matches := true
	access_log_entry_type := cilium.EntryType_Request

	if !p.connection.Matches(reqData) {
		matches = false
		access_log_entry_type = cilium.EntryType_Denied
	}

	p.connection.Log(access_log_entry_type,
		&cilium.LogEntry_GenericL7{
			&cilium.L7LogEntry{
				Proto: "aws-dynamoDB",
				Fields: map[string]string{
					"action": reqData.action,
					"table":  reqData.table,
				},
			},
		})

	if !matches {
		p.connection.Inject(true, []byte(DynamoDBAccessDeniedStr))
		return DROP, reqLen
	}
	return PASS, reqLen
}

// map to test whether a 'action' is valid or not
// and whether it is compatible with an associated table

const invalidAction = 0
const actionWithTable = 1
const actionWithGlobalTable = 2
const actionNoTable = 3

var DynamoDBActionMap = map[string]int{
	"BatchGetItem":                invalidAction, // policy should be applied directly against individual ops
	"BatchWriteItem":              invalidAction, // policy should be applied directly against individual ops
	"CreateGlobalTable":           actionWithGlobalTable,
	"CreateTable":                 actionWithTable,
	"DeleteBackup":                actionNoTable, // policy matching on backup ARNs not supported
	"DeleteItem":                  actionWithTable,
	"DeleteTable":                 actionWithTable,
	"DescribeBackup":              actionNoTable, // policy matching on backup ARNs not supported
	"DescribeContinuousBackups":   actionWithTable,
	"DescribeGlobalTable":         actionWithGlobalTable,
	"DescribeGlobalTableSettings": actionWithGlobalTable,
	"DescribeLimits":              actionNoTable,
	"DescribeTable":               actionWithTable,
	"DescribeTimeToLive":          actionWithTable,
	"GetItem":                     actionWithTable,
	"ListBackups":                 actionWithTable,
	"ListGlobalTables":            actionNoTable,
	"ListTables":                  actionNoTable,
	"ListTagsOfResource":          actionNoTable,
	"PutItem":                     actionWithTable,
	"Query":                       actionWithTable,
	"RestoreTableFromBackup":      actionNoTable, // policy matching on backup ARN not supported
	"RestoreTableToPointInTime":   actionNoTable, // policy matching in backup tables not supported
	"Scan":                        actionWithTable,
	"TagResource":                 actionNoTable,
	"UntagResource":               actionNoTable,
	"UpdateContinuousBackups":     actionWithTable,
	"UpdateGlobalTable":           actionWithGlobalTable,
	"UpdateGlobalTableSettings":   actionWithGlobalTable,
	"UpdateItem":                  actionWithTable,
	"UpdateTable":                 actionWithTable,
	"UpdateTimeToLive":            actionWithTable,
}

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
	"fmt"
	. "github.com/cilium/cilium/proxylib/proxylib"
	"regexp"
	"strings"

	"github.com/cilium/proxy/go/cilium/api"
	log "github.com/sirupsen/logrus"
	"net/url"
)

//
// AWS Simple Queuing Service (SQS) Parser
//
// Spec: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-making-api-requests.html
//       https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/Welcome.html
//

// Current AWS SQS parser supports matching on 'Action' and 'QueueName', both of which can be wildcarded.
// QueueName can be a regular expression.  Per the AWS spec, queue names are case sensitive.
// Examples:
// action = 'CreateQueue', queue_name = 'MyQueue'

type AWSSQSRule struct {
	actionExact            string
	queueNameRegexCompiled *regexp.Regexp
}

type AWSSQSRequestData struct {
	action    string
	queueName string
}

func (rule *AWSSQSRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	reqData, ok := data.(AWSSQSRequestData)
	if !ok {
		log.Warning("Matches() called with type other than string")
		return false
	}
	log.Infof("Match Request: action '%s' queueName '%s'", reqData.action, reqData.queueName)
	regexStr := ""
	if rule.queueNameRegexCompiled != nil {
		regexStr = rule.queueNameRegexCompiled.String()
	}
	log.Infof("Match Rule: action '%s', queue '%s'", rule.actionExact, regexStr)

	if rule.actionExact != "" && rule.actionExact != reqData.action {
		log.Debugf("AWSSQSRule: action mismatch %v, %s", rule.actionExact, reqData.action)
		return false
	}
	if len(reqData.queueName) > 0 &&
		rule.queueNameRegexCompiled != nil &&
		!rule.queueNameRegexCompiled.MatchString(reqData.queueName) {
		log.Debugf("AWSSQSRule: queue_regex mismatch '%v', '%s'", regexStr, reqData.queueName)
		return false
	}

	return true
}

// AWSSQSRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func AWSSQSRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	var rules []L7NetworkPolicyRule
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return rules
	}
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var r AWSSQSRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "action":
				r.actionExact = v
			case "queue_name":
				if v != "" {
					r.queueNameRegexCompiled = regexp.MustCompile(v)
				}
			default:
				ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if len(r.actionExact) > 0 {
			// ensure this is a valid query action
			res := SQSActionMap[r.actionExact]
			if res == SQSInvalidAction {
				ParseError(fmt.Sprintf("Unable to parse L7 AWS-SQS rule with invalid action: '%s'", r.actionExact), rule)
			} else if res == SQSActionNoQueue && r.queueNameRegexCompiled != nil {
				ParseError(fmt.Sprintf("action '%s' is not compatible with a queue_name match", r.actionExact), rule)
			}

		}

		log.Debugf("Parsed AWSSQSRule pair: %v", r)
		rules = append(rules, &r)
	}
	return rules
}

type AWSSQSParserFactory struct{}

var awsSQSParserFactory *AWSSQSParserFactory

func init() {
	log.Info("init(): Registering AWSSQSParserFactory")
	RegisterParserFactory("aws-sqs", awsSQSParserFactory)
	RegisterL7RuleParser("aws-sqs", AWSSQSRuleParser)
}

type AWSSQSParser struct {
	connection *Connection
	inserted   bool
}

func (pf *AWSSQSParserFactory) Create(connection *Connection) Parser {
	log.Debugf("AWSSQSParserFactory: Create: %v", connection)

	p := AWSSQSParser{connection: connection}
	return &p
}

// See: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/CommonErrors.html
// For some reason, the above page indicates that SQS returns a 400, not a 403 in the case of
// access denied.
var SQSAccessDeniedStr string = "HTTP/1.1 400 Bad Request\r\n" +
	"Content-Type: text/xml\r\n" +
	"Content-Length: 275\r\n" +
	"\r\n" +
	`<?xml version="1.0"?><ErrorResponse xmlns="http://queue.amazonaws.com/doc/2012-11-05/"><Error><Type>Sender</Type><Code>AWS.SimpleQueueService.AccessDeniedException</Code><Message>The request has been denied by Cilium Network Policy.</Message><Detail/></Error></ErrorResponse>`

func (p *AWSSQSParser) OnData(reply, endStream bool, dataArray [][]byte) (OpType, int) {

	// inefficient, but simple for now
	data := bytes.Join(dataArray, []byte{})

	log.Infof("AWS-SQS onData with length %d, reply %v", len(data), reply)
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

	log.Infof("parsing request")
	req, reqLen, needs := parseHTTPRequest(data)
	if req == nil {
		if needs < 0 {
			log.Infof("Error Trying to Parse header")
			return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
		} else {
			log.Infof("Incomplete header, waiting for more data")
			return MORE, needs
		}
	}

	queue := ""
	action := req.FormValue("Action")
	if action == "CreateQueue" {
		queue = req.FormValue("QueueName")
	} else {

		// Use QueueUrl paramter if provided, otherwise,
		// try to parse from URL
		// TODO:  need to validate what
		// AWS does when these two differ
		queueURL := req.URL
		queueURLParam := req.FormValue("QueueUrl")
		if len(queueURLParam) > 0 {
			queueURL, _ = url.Parse(queueURLParam)
		}
		queueUrlParts := strings.Split(queueURL.Path, "/")
		if len(queueUrlParts) > 0 {
			queue = queueUrlParts[len(queueUrlParts)-1]
		}
	}
	log.Infof("queue: '%s'  action: '%s'", queue, action)
	if len(queue) == 0 || len(action) == 0 {
		log.Errorf("Failed to parse queue '%s' or action '%s'", queue, action)
		return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
	}

	reqData := AWSSQSRequestData{action: action, queueName: queue}

	matches := true
	access_log_entry_type := cilium.EntryType_Request

	if !p.connection.Matches(reqData) {
		matches = false
		access_log_entry_type = cilium.EntryType_Denied
	}

	p.connection.Log(access_log_entry_type,
		&cilium.LogEntry_GenericL7{
			&cilium.L7LogEntry{
				Proto: "aws-sqs",
				Fields: map[string]string{
					"action":     reqData.action,
					"queue_name": reqData.queueName,
				},
			},
		})

	if !matches {
		p.connection.Inject(true, []byte(SQSAccessDeniedStr))
		return DROP, reqLen
	}
	return PASS, reqLen
}

// map to test whether a 'action' is valid or not
// and whether it is compatible with an associated queue-name

const SQSInvalidAction = 0
const SQSActionWithQueue = 1
const SQSActionNoQueue = 2

var SQSActionMap = map[string]int{
	"AddPermission":                SQSActionWithQueue,
	"ChangeMessageVisibility":      SQSActionWithQueue,
	"ChangeMessageVisibilityBatch": SQSActionWithQueue,
	"CreateQueue":                  SQSActionWithQueue,
	"DeleteMessage":                SQSActionWithQueue,
	"DeleteMessageBatch":           SQSActionWithQueue,
	"DeleteQueue":                  SQSActionWithQueue,
	"GetQueueAttributes":           SQSActionWithQueue,
	"GetQueueUrl":                  SQSActionWithQueue,
	"ListDeadLetterSourceQueues":   SQSActionNoQueue,
	"ListQueues":                   SQSActionNoQueue,
	"ListQueueTags":                SQSActionWithQueue,
	"PurgeQueue":                   SQSActionWithQueue,
	"ReceiveMessage":               SQSActionWithQueue,
	"RemovePermission":             SQSActionWithQueue,
	"SendMessage":                  SQSActionWithQueue,
	"SendMessageBatch":             SQSActionWithQueue,
	"SetQueueAttributes":           SQSActionWithQueue,
	"TagQueue":                     SQSActionWithQueue,
	"UntagQueue":                   SQSActionWithQueue,
}

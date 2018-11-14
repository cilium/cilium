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
	"bufio"
	"bytes"
	"fmt"
	"regexp"

	. "github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/proxy/go/cilium"
	log "github.com/sirupsen/logrus"
	"net/http"
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

var AccessDeniedStr string = "HTTP/1.1 403 Access Denied\r\n\r\n"

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
		log.Debugf("AWSSQSRule: queue_regex mismatch '%v', '%s'", rule.queueNameRegexCompiled, reqData.queueName)
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
			res := actionMap[r.actionExact]
			if res == invalidAction {
				ParseError(fmt.Sprintf("Unable to parse L7 AWS-SQS rule with invalid action: '%s'", r.actionExact), rule)
			} else if res == actionNoQueue && r.queueNameRegexCompiled != nil {
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

func (p *AWSSQSParser) OnData(reply, endStream bool, dataArray [][]byte) (OpType, int) {

	// inefficient, but simple for now
	data := bytes.Join(dataArray, []byte{})

	// TODO:  we should refactor this out into some generic HTTP parsing library
	headerLen := 0
	for i := 0; i < len(data)-3; i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			headerLen = i + 4
			break // exit at first end of header
		}
	}
	if headerLen == 0 {
		// don't have full header
		return MORE, 1
	}
	bReader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(bReader)
	if err != nil {
		// malformed request
		// TODO:  find better error type
		return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
	}
	totalReqLen := headerLen + int(req.ContentLength)
	if totalReqLen > len(data) {
		return MORE, totalReqLen - len(data)
	}

	queue := ""

	// Use QueueUrl paramter if provided, otherwise,
	// try to parse from URL
	// TODO:  need to validate what
	// AWS does when these two differ
	queueURL := req.URL
	queueURLParam := req.FormValue("QueueUrl")
	if len(queueURLParam) > 0 {
		queueURL, err = url.Parse(queueURLParam)
	}
	queue = queueURL.Path[1:]
	if queue[len(queue)-1] == '/' {
		queue = queue[0:(len(queue) - 1)]
	}
	action := req.FormValue("Action")
	log.Infof("queue: %s  action: %s", queue, action)

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
		p.connection.Inject(true, []byte(AccessDeniedStr))
		return DROP, totalReqLen
	}
	return PASS, totalReqLen
}

// map to test whether a 'action' is valid or not
// and whether it is compatible with an associated queue-name

const invalidAction = 0
const actionWithQueue = 1
const actionNoQueue = 2

var actionMap = map[string]int{
	"AddPermission":                actionWithQueue,
	"ChangeMessageVisibility":      actionWithQueue,
	"ChangeMessageVisibilityBatch": actionWithQueue,
	"CreateQueue":                  actionWithQueue,
	"DeleteMessage":                actionWithQueue,
	"DeleteMessageBatch":           actionWithQueue,
	"DeleteQueue":                  actionWithQueue,
	"GetQueueAttributes":           actionWithQueue,
	"GetQueueUrl":                  actionWithQueue,
	"ListDeadLetterSourceQueues":   actionNoQueue,
	"ListQueues":                   actionNoQueue,
	"ListQueueTags":                actionWithQueue,
	"PurgeQueue":                   actionWithQueue,
	"ReceiveMessage":               actionWithQueue,
	"RemovePermission":             actionWithQueue,
	"SendMessage":                  actionWithQueue,
	"SendMessageBatch":             actionWithQueue,
	"SetQueueAttributes":           actionWithQueue,
	"TagQueue":                     actionWithQueue,
	"UntagQueue":                   actionWithQueue,
}

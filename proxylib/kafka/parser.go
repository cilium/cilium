// Copyright 2020 Authors of Cilium
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

package kafka

import (
	"encoding/binary"

	. "github.com/cilium/cilium/proxylib/proxylib"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/kafka"
	cilium "github.com/cilium/proxy/go/cilium/api"

	log "github.com/sirupsen/logrus"
)

const (
	parserName = "kafka"
)

// KafkaRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func KafkaRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	l7Rules := rule.GetKafkaRules()
	if l7Rules == nil {
		return nil
	}

	allowRules := l7Rules.GetKafkaRules()
	rules := make([]L7NetworkPolicyRule, 0, len(allowRules))
	for _, r := range allowRules {
		rules = append(rules, kafka.NewRule(r.ApiVersion, r.ApiKeys, r.ClientId, r.Topic))
	}
	return rules
}

type KafkaParserFactory struct{}

var kafkaParserFactory *KafkaParserFactory

func init() {
	log.Info("init(): Registering kafkaParserFactory")
	RegisterParserFactory(parserName, kafkaParserFactory)
	RegisterL7RuleParser(parserName, KafkaRuleParser)
}

type KafkaParser struct {
	connection *Connection
}

func (pf *KafkaParserFactory) Create(connection *Connection) interface{} {
	p := KafkaParser{connection: connection}
	return &p
}

func (p *KafkaParser) OnData(reply bool, reader *Reader) (OpType, int) {
	length := reader.Length()
	if length == 0 {
		return NOP, 0
	}

	correlationID := int32(0)
	framelength := 4          // account for the length field
	lenbuf := make([]byte, 8) // Peek the first eight bytes
	n, err := reader.PeekFull(lenbuf)
	if err == nil {
		framelength += int(binary.BigEndian.Uint32(lenbuf[:4]))
		correlationID = int32(binary.BigEndian.Uint32(lenbuf[4:]))
	} else {
		// Need more data
		return MORE, 8 - n
	}

	if reply {
		// Replies are always passed as-is. No need to parse them
		// on top of the frame length and correlation ID.
		p.connection.Log(cilium.EntryType_Response,
			&cilium.LogEntry_Kafka{Kafka: &cilium.KafkaLogEntry{
				CorrelationId: correlationID,
			}})
		return PASS, framelength
	}

	// Ask for more if full frame has not been received yet
	if length < framelength {
		// Not enough data, ask for more and try again
		return MORE, framelength - length
	}

	req, err := kafka.ReadRequest(reader)
	if err != nil {
		if flowdebug.Enabled() {
			log.WithError(err).Warning("Unable to parse Kafka request; closing Kafka connection")
		}
		p.connection.Log(cilium.EntryType_Denied,
			&cilium.LogEntry_Kafka{Kafka: &cilium.KafkaLogEntry{
				CorrelationId: correlationID,
				ErrorCode:     kafka.ErrInvalidMessage,
			}})
		return ERROR, int(ERROR_INVALID_FRAME_TYPE)
	}

	logEntry := &cilium.LogEntry_Kafka{Kafka: &cilium.KafkaLogEntry{
		CorrelationId: correlationID,
		ApiVersion:    int32(req.GetVersion()),
		ApiKey:        int32(req.GetAPIKey()),
		Topics:        req.GetTopics(),
	}}
	if p.connection.Matches(req) {
		p.connection.Log(cilium.EntryType_Request, logEntry)
		return PASS, framelength
	}
	logEntry.Kafka.ErrorCode = kafka.ErrTopicAuthorizationFailed

	resp, err := req.CreateAuthErrorResponse()
	if err != nil {
		if flowdebug.Enabled() {
			log.WithError(err).Warning("Unable to create Kafka response")
		}
	} else {
		// inject response
		p.connection.Inject(!reply, resp.GetRaw())
	}

	p.connection.Log(cilium.EntryType_Denied, logEntry)
	return DROP, framelength
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kafka

import (
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/cilium/kafka/proto"

	"github.com/cilium/cilium/pkg/policy/api/kafka"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type kafkaTestSuite struct{}

var _ = Suite(&kafkaTestSuite{})

var (
	messages = make([]*proto.Message, 100)
)

func (k *kafkaTestSuite) SetUpTest(c *C) {
	for i := range messages {
		messages[i] = &proto.Message{
			Offset: int64(i),
			Crc:    uint32(i),
			Key:    nil,
			Value:  []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur.`),
		}

	}
}

// MatchesRule validates the Kafka request message against the provided list of
// rules. The function will return true if the policy allows the message,
// otherwise false is returned.
func (req *RequestMessage) MatchesRule(rules []Rule) bool {
	for _, rule := range rules {
		if rule.Matches(req) {
			return true
		}
	}
	return false
}

func (k *kafkaTestSuite) TestProduceRequest(c *C) {
	req := &proto.ProduceReq{
		CorrelationID: 241,
		ClientID:      "test",
		Compression:   proto.CompressionNone,
		RequiredAcks:  proto.RequiredAcksAll,
		Timeout:       time.Second,
		Topics: []proto.ProduceReqTopic{
			{
				Name: "foo",
				Partitions: []proto.ProduceReqPartition{
					{
						ID:       0,
						Messages: messages,
					},
				},
			},
			{
				Name: "bar",
				Partitions: []proto.ProduceReqPartition{
					{
						ID:       0,
						Messages: messages,
					},
				},
			},
		},
	}

	reqMsg := RequestMessage{
		request: req,
	}

	// empty rules should match nothing
	reqMsg.setTopics()
	c.Assert(reqMsg.MatchesRule([]Rule{}), Equals, false)

	// wildcard rule matches everything
	reqMsg.setTopics()
	c.Assert(reqMsg.MatchesRule([]Rule{{}}), Equals, true)

	reqMsg.setTopics()
	c.Assert(reqMsg.MatchesRule([]Rule{
		NewRule(-1, nil, "", "foo"),
	}), Equals, false)

	reqMsg.setTopics()
	c.Assert(reqMsg.MatchesRule([]Rule{
		NewRule(-1, nil, "", "foo"), NewRule(-1, nil, "", "bar"),
	}), Equals, true)

	reqMsg.setTopics()
	c.Assert(reqMsg.MatchesRule([]Rule{
		NewRule(-1, nil, "", "foo"), NewRule(-1, nil, "", "baz"),
	}), Equals, false)

	reqMsg.setTopics()
	c.Assert(reqMsg.MatchesRule([]Rule{
		NewRule(-1, nil, "", "baz"), NewRule(-1, nil, "", "foo2"),
	}), Equals, false)

	reqMsg.setTopics()
	c.Assert(reqMsg.MatchesRule([]Rule{
		NewRule(-1, nil, "", "bar"), NewRule(-1, nil, "", "foo"),
	}), Equals, true)

	reqMsg.setTopics()
	c.Assert(reqMsg.MatchesRule([]Rule{
		NewRule(-1, nil, "", "bar"), NewRule(-1, nil, "", "foo"), NewRule(-1, nil, "", "baz")}), Equals, true)

}

func (k *kafkaTestSuite) TestUnknownRequest(c *C) {
	reqMsg := RequestMessage{kind: 18} // ApiVersions request

	// Empty rule should disallow
	c.Assert(reqMsg.MatchesRule([]Rule{}), Equals, false)

	// Whitelisting of unknown message
	rule1 := NewRule(-1, []int32{int32(kafka.MetadataKey)}, "", "")
	rule2 := NewRule(-1, []int32{int32(kafka.APIVersionsKey)}, "", "")
	c.Assert(reqMsg.MatchesRule([]Rule{rule1, rule2}), Equals, true)

	reqMsg = RequestMessage{kind: 19}
	c.Assert(reqMsg.MatchesRule([]Rule{rule1, rule2}), Equals, false)
}

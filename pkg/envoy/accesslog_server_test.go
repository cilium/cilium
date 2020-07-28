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

// +build !privileged_tests

package envoy

import (
	"encoding/json"

	"github.com/cilium/cilium/pkg/proxy/logger"
	logger_test "github.com/cilium/cilium/pkg/proxy/logger/test"

	"github.com/cilium/proxy/go/cilium/api"

	. "gopkg.in/check.v1"
)

type AccessLogServerSuite struct{}

var _ = Suite(&AccessLogServerSuite{})

func (k *AccessLogServerSuite) TestParseURL(c *C) {
	logs := []cilium.HttpLogEntry{
		{Scheme: "http", Host: "foo", Path: "/foo?blah=131"},
		{Scheme: "http", Host: "foo", Path: "foo?blah=131"},
		{Scheme: "http", Host: "foo", Path: "/foo"},
	}

	for _, l := range logs {
		u := ParseURL(l.Scheme, l.Host, l.Path)
		c.Assert(u.Scheme, Equals, "http")
		c.Assert(u.Host, Equals, "foo")
		c.Assert(u.Path, Equals, "/foo")
	}
}

type testNotifier struct {
	http  []string
	kafka []string
	l7    []string
}

func (n *testNotifier) NewProxyLogRecord(l *logger.LogRecord) error {
	if l.HTTP != nil {
		jsn, _ := json.Marshal(l.HTTP)
		n.http = append(n.http, string(jsn))
	}
	if l.Kafka != nil {
		jsn, _ := json.Marshal(l.Kafka)
		n.kafka = append(n.kafka, string(jsn))
	}
	if l.L7 != nil {
		jsn, _ := json.Marshal(l.L7)
		n.l7 = append(n.l7, string(jsn))
	}
	return nil
}

func (k *AccessLogServerSuite) TestKafkaLogNoTopic(c *C) {
	notifier := &testNotifier{}
	logger.SetNotifier(notifier)
	logRecord(&dummyEndpointInfoRegistry{}, &logger_test.ProxyUpdaterMock{}, &cilium.LogEntry{
		L7: &cilium.LogEntry_Kafka{Kafka: &cilium.KafkaLogEntry{
			CorrelationId: 76541,
			ErrorCode:     42,
			ApiVersion:    3,
			ApiKey:        1,
		}},
	})

	c.Assert(notifier.kafka, HasLen, 1)
	c.Assert(notifier.kafka[0], Equals, `{"ErrorCode":42,"APIVersion":3,"APIKey":"fetch","CorrelationID":76541,"Topic":{}}`)
}

func (k *AccessLogServerSuite) TestKafkaLogSingleTopic(c *C) {
	notifier := &testNotifier{}
	logger.SetNotifier(notifier)
	logRecord(&dummyEndpointInfoRegistry{}, &logger_test.ProxyUpdaterMock{}, &cilium.LogEntry{
		L7: &cilium.LogEntry_Kafka{Kafka: &cilium.KafkaLogEntry{
			CorrelationId: 76541,
			ErrorCode:     42,
			ApiVersion:    3,
			ApiKey:        1,
			Topics:        []string{"topic 1"},
		}},
	})

	c.Assert(notifier.kafka, HasLen, 1)
	c.Assert(notifier.kafka[0], Equals, `{"ErrorCode":42,"APIVersion":3,"APIKey":"fetch","CorrelationID":76541,"Topic":{"Topic":"topic 1"}}`)
}

// TestKafkaLogMultipleTopics checks that a cilium.KafkaLogEntry with
// multiple topics is split into multiple log messages, one per topic
func (k *AccessLogServerSuite) TestKafkaLogMultipleTopics(c *C) {
	notifier := &testNotifier{}
	logger.SetNotifier(notifier)
	logRecord(&dummyEndpointInfoRegistry{}, &logger_test.ProxyUpdaterMock{}, &cilium.LogEntry{
		L7: &cilium.LogEntry_Kafka{Kafka: &cilium.KafkaLogEntry{
			CorrelationId: 76541,
			ErrorCode:     42,
			ApiVersion:    3,
			ApiKey:        1,
			Topics:        []string{"topic 1", "topic 2"},
		}},
	})

	c.Assert(notifier.kafka, HasLen, 2)
	c.Assert(notifier.kafka[0], Equals, `{"ErrorCode":42,"APIVersion":3,"APIKey":"fetch","CorrelationID":76541,"Topic":{"Topic":"topic 1"}}`)
	c.Assert(notifier.kafka[1], Equals, `{"ErrorCode":42,"APIVersion":3,"APIKey":"fetch","CorrelationID":76541,"Topic":{"Topic":"topic 2"}}`)
}

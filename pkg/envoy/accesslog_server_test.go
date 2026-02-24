// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cilium/hive/hivetest"
	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

func TestParseURL(t *testing.T) {
	logs := []*cilium.HttpLogEntry{
		{Scheme: "http", Host: "foo", Path: "/foo?blah=131"},
		{Scheme: "http", Host: "foo", Path: "foo?blah=131"},
		{Scheme: "http", Host: "foo", Path: "/foo"},
	}

	for _, l := range logs {
		u := ParseURL(l.Scheme, l.Host, l.Path)
		require.Equal(t, "http", u.Scheme)
		require.Equal(t, "foo", u.Host)
		require.Equal(t, "/foo", u.Path)
	}
}

type testNotifier struct {
	http  []string
	kafka []string
	l7    []string
}

func (n *testNotifier) NewProxyLogRecord(l *accesslog.LogRecord) error {
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

func TestKafkaLogNoTopic(t *testing.T) {
	node.WithTestLocalNodeStore(func() {
		notifier := &testNotifier{}
		accessLogServer := newTestAccessLogServer(t, notifier)
		accessLogServer.logRecord(context.Background(), &cilium.LogEntry{
			L7: &cilium.LogEntry_Kafka{Kafka: &cilium.KafkaLogEntry{
				CorrelationId: 76541,
				ErrorCode:     42,
				ApiVersion:    3,
				ApiKey:        1,
			}},
		})

		require.Len(t, notifier.kafka, 1)
		require.JSONEq(t, `{"ErrorCode":42,"APIVersion":3,"APIKey":"fetch","CorrelationID":76541,"Topic":{}}`, notifier.kafka[0])
	})
}

func TestKafkaLogSingleTopic(t *testing.T) {
	node.WithTestLocalNodeStore(func() {
		notifier := &testNotifier{}
		accessLogServer := newTestAccessLogServer(t, notifier)
		accessLogServer.logRecord(context.Background(), &cilium.LogEntry{
			L7: &cilium.LogEntry_Kafka{Kafka: &cilium.KafkaLogEntry{
				CorrelationId: 76541,
				ErrorCode:     42,
				ApiVersion:    3,
				ApiKey:        1,
				Topics:        []string{"topic 1"},
			}},
		})

		require.Len(t, notifier.kafka, 1)
		require.JSONEq(t, `{"ErrorCode":42,"APIVersion":3,"APIKey":"fetch","CorrelationID":76541,"Topic":{"Topic":"topic 1"}}`, notifier.kafka[0])
	})
}

// TestKafkaLogMultipleTopics checks that a cilium.KafkaLogEntry with
// multiple topics is split into multiple log messages, one per topic
func TestKafkaLogMultipleTopics(t *testing.T) {
	node.WithTestLocalNodeStore(func() {
		notifier := &testNotifier{}
		accessLogServer := newTestAccessLogServer(t, notifier)
		accessLogServer.logRecord(context.Background(), &cilium.LogEntry{
			L7: &cilium.LogEntry_Kafka{Kafka: &cilium.KafkaLogEntry{
				CorrelationId: 76541,
				ErrorCode:     42,
				ApiVersion:    3,
				ApiKey:        1,
				Topics:        []string{"topic 1", "topic 2"},
			}},
		})

		require.Len(t, notifier.kafka, 2)
		require.JSONEq(t, `{"ErrorCode":42,"APIVersion":3,"APIKey":"fetch","CorrelationID":76541,"Topic":{"Topic":"topic 1"}}`, notifier.kafka[0])
		require.JSONEq(t, `{"ErrorCode":42,"APIVersion":3,"APIKey":"fetch","CorrelationID":76541,"Topic":{"Topic":"topic 2"}}`, notifier.kafka[1])
	})
}

func newTestAccessLogServer(t *testing.T, notifier accesslog.LogRecordNotifier) *AccessLogServer {
	accessLogger := accesslog.NewProxyAccessLogger(hivetest.Logger(t), accesslog.ProxyAccessLoggerConfig{}, notifier, nil)
	return newAccessLogServer(hivetest.Logger(t), accessLogger, "", 0, nil, 0)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"fmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	"github.com/cilium/cilium/pkg/hubble/ir"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

func decodeKafka(flowType accesslog.FlowType, kafka *accesslog.LogRecordKafka, opts *options.Options) ir.Kafka {
	// Conditionally exclude the API key from the flow.
	var apiKey string
	if opts.HubbleRedactSettings.RedactKafkaAPIKey {
		apiKey = defaults.SensitiveValueRedacted
	} else {
		apiKey = kafka.APIKey
	}

	if flowType == accesslog.TypeRequest {
		// Set only fields that are relevant for requests.
		return ir.Kafka{
			APIVersion:    int32(kafka.APIVersion),
			APIKey:        apiKey,
			CorrelationId: kafka.CorrelationID,
			Topic:         kafka.Topic.Topic,
		}
	}
	return ir.Kafka{
		ErrorCode:     int32(kafka.ErrorCode),
		APIVersion:    int32(kafka.APIVersion),
		APIKey:        apiKey,
		CorrelationId: kafka.CorrelationID,
		Topic:         kafka.Topic.Topic,
	}
}

func kafkaSummary(flow *ir.Flow) string {
	if flow == nil {
		return ""
	}
	kafka := flow.L7.Kafka
	if kafka.IsEmpty() {
		return ""
	}
	if flow.L7.Type == flowpb.L7FlowType_REQUEST {
		return fmt.Sprintf("Kafka request %s correlation id %d topic '%s'",
			kafka.APIKey,
			kafka.CorrelationId,
			kafka.Topic)
	}
	// response
	return fmt.Sprintf("Kafka response %s correlation id %d topic '%s' return code %d",
		kafka.APIKey,
		kafka.CorrelationId,
		kafka.Topic,
		kafka.ErrorCode)
}

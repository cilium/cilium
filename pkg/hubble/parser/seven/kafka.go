// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"fmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

func decodeKafka(flowType accesslog.FlowType, kafka *accesslog.LogRecordKafka, opts *options.Options) *flowpb.Layer7_Kafka {
	// Conditionally exclude the API key from the flow.
	var apiKey string
	if opts.HubbleRedactSettings.RedactKafkaAPIKey {
		apiKey = defaults.SensitiveValueRedacted
	} else {
		apiKey = kafka.APIKey
	}

	if flowType == accesslog.TypeRequest {
		// Set only fields that are relevant for requests.
		return &flowpb.Layer7_Kafka{
			Kafka: &flowpb.Kafka{
				ApiVersion:    int32(kafka.APIVersion),
				ApiKey:        apiKey,
				CorrelationId: kafka.CorrelationID,
				Topic:         kafka.Topic.Topic,
			},
		}
	}
	return &flowpb.Layer7_Kafka{
		Kafka: &flowpb.Kafka{
			ErrorCode:     int32(kafka.ErrorCode),
			ApiVersion:    int32(kafka.APIVersion),
			ApiKey:        apiKey,
			CorrelationId: kafka.CorrelationID,
			Topic:         kafka.Topic.Topic,
		},
	}
}

func kafkaSummary(flow *flowpb.Flow) string {
	kafka := flow.GetL7().GetKafka()
	if kafka == nil {
		return ""
	}
	if flow.GetL7().Type == flowpb.L7FlowType_REQUEST {
		return fmt.Sprintf("Kafka request %s correlation id %d topic '%s'",
			kafka.ApiKey,
			kafka.CorrelationId,
			kafka.Topic)
	}
	// response
	return fmt.Sprintf("Kafka response %s correlation id %d topic '%s' return code %d",
		kafka.ApiKey,
		kafka.CorrelationId,
		kafka.Topic,
		kafka.ErrorCode)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"reflect"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

func Test_decodeKafka(t *testing.T) {
	type args struct {
		flowType accesslog.FlowType
		kafka    *accesslog.LogRecordKafka
	}
	tests := []struct {
		name string
		args args
		want *flowpb.Layer7_Kafka
	}{
		{
			name: "request",
			args: args{
				flowType: accesslog.TypeRequest,
				kafka: &accesslog.LogRecordKafka{
					ErrorCode:     1,
					APIVersion:    2,
					APIKey:        "publish",
					CorrelationID: 3,
					Topic: accesslog.KafkaTopic{
						Topic: "my-topic",
					},
				},
			},
			want: &flowpb.Layer7_Kafka{
				Kafka: &flowpb.Kafka{
					ApiVersion:    2,
					ApiKey:        "publish",
					CorrelationId: 3,
					Topic:         "my-topic",
				},
			},
		},
		{
			name: "response",
			args: args{
				flowType: accesslog.TypeResponse,
				kafka: &accesslog.LogRecordKafka{
					ErrorCode:     1,
					APIVersion:    2,
					APIKey:        "publish",
					CorrelationID: 3,
					Topic: accesslog.KafkaTopic{
						Topic: "my-topic",
					},
				},
			},
			want: &flowpb.Layer7_Kafka{
				Kafka: &flowpb.Kafka{
					ErrorCode:     1,
					ApiVersion:    2,
					ApiKey:        "publish",
					CorrelationId: 3,
					Topic:         "my-topic",
				},
			},
		},
		{
			name: "empty-topic",
			args: args{
				flowType: accesslog.TypeResponse,
				kafka: &accesslog.LogRecordKafka{
					ErrorCode:     1,
					APIVersion:    2,
					APIKey:        "publish",
					CorrelationID: 3,
				},
			},
			want: &flowpb.Layer7_Kafka{
				Kafka: &flowpb.Kafka{
					ErrorCode:     1,
					ApiVersion:    2,
					ApiKey:        "publish",
					CorrelationId: 3,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeKafka(tt.args.flowType, tt.args.kafka); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeKafka() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_kafkaSummary(t *testing.T) {
	type args struct {
		flow *flowpb.Flow
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			name: "request",
			args: args{
				flow: &flowpb.Flow{
					L7: &flowpb.Layer7{
						Type: flowpb.L7FlowType_REQUEST,
						Record: &flowpb.Layer7_Kafka{
							Kafka: &flowpb.Kafka{
								ErrorCode:     1,
								ApiVersion:    2,
								ApiKey:        "publish",
								CorrelationId: 3,
								Topic:         "my-topic",
							},
						},
					},
				},
			},
			want: "Kafka request publish correlation id 3 topic 'my-topic'",
		},
		{
			name: "response",
			args: args{
				flow: &flowpb.Flow{
					L7: &flowpb.Layer7{
						Type: flowpb.L7FlowType_RESPONSE,
						Record: &flowpb.Layer7_Kafka{
							Kafka: &flowpb.Kafka{
								ErrorCode:     1,
								ApiVersion:    2,
								ApiKey:        "publish",
								CorrelationId: 3,
								Topic:         "my-topic",
							},
						},
					},
				},
			},
			want: "Kafka response publish correlation id 3 topic 'my-topic' return code 1",
		},
		{
			name: "nil",
			args: args{
				flow: nil,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kafkaSummary(tt.args.flow); got != tt.want {
				t.Errorf("kafkaSummary() = %v, want %v", got, tt.want)
			}
		})
	}
}

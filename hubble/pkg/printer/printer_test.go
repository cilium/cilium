// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package printer

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/pkg/defaults"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

var (
	f = flowpb.Flow{
		Time: &timestamppb.Timestamp{
			Seconds: 1234,
			Nanos:   567800000,
		},
		Type:     flowpb.FlowType_L3_L4,
		NodeName: "k8s1",
		Verdict:  flowpb.Verdict_DROPPED,
		IP: &flowpb.IP{
			Source:      "1.1.1.1",
			Destination: "2.2.2.2",
		},
		Source: &flowpb.Endpoint{
			Identity: 4,
		},
		Destination: &flowpb.Endpoint{
			Identity: 12345,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					SourcePort:      31793,
					DestinationPort: 8080,
				},
			},
		},
		EventType: &flowpb.CiliumEventType{
			Type:    monitorAPI.MessageTypeDrop,
			SubType: 133,
		},
		Summary: "TCP Flags: SYN",
		IsReply: &wrapperspb.BoolValue{Value: false},
	}

	kafkaUnescapedFlow = flowpb.Flow{
		Time: &timestamppb.Timestamp{
			Seconds: 1234,
			Nanos:   567800000,
		},
		Type:     flowpb.FlowType_L7,
		NodeName: "k8s1",
		Verdict:  flowpb.Verdict_DROPPED,
		IP: &flowpb.IP{
			Source:      "1.1.1.1",
			Destination: "2.2.2.2",
		},
		Source: &flowpb.Endpoint{
			Identity: 4,
		},
		Destination: &flowpb.Endpoint{
			Identity: 12345,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					SourcePort:      31793,
					DestinationPort: 8080,
				},
			},
		},
		L7: &flowpb.Layer7{
			Type:      flowpb.L7FlowType_REQUEST,
			LatencyNs: *proto.Uint64(10),
			Record: &flowpb.Layer7_Kafka{Kafka: &flowpb.Kafka{
				ApiKey:        "1234",
				CorrelationId: *proto.Int32(1),
				// Black color, arbitrary control char and carriage-returns are not allowed, will be escaped
				// Printer output that uses color will have color control sequences unescaped
				Topic: "my-topic\x1b[30mblack\x1b[0m\x1b\r",
			}},
		},
		EventType: &flowpb.CiliumEventType{
			Type:    monitorAPI.MessageTypeDrop,
			SubType: 133,
		},
		Summary: "Kafka request 1234 correlation id 1 topic 'my-topic[^[30mblack[^[0m[^\\r'",
		IsReply: &wrapperspb.BoolValue{Value: false},
	}
)

func TestPrinter_AllFieldsInMask(t *testing.T) {
	fm := make(map[string]bool)
	for _, field := range defaults.FieldMask {
		fm[field] = true
	}
	check := func(msg protoreflect.Message, prefix string) {
		fds := msg.Descriptor().Fields()
		for i := 0; i < fds.Len(); i++ {
			fd := fds.Get(i)
			if !msg.Has(fd) {
				continue
			}
			name := prefix + string(fd.Name())
			if name == "source" || name == "destination" {
				// Skip compound fields.
				continue
			}
			assert.True(t, fm[name], name)
		}
	}
	check(f.ProtoReflect(), "")
	check(f.GetSource().ProtoReflect(), "source.")
	check(f.GetDestination().ProtoReflect(), "destination.")
}

func TestPrinter_WriteProtoFlow(t *testing.T) {
	buf := bytes.Buffer{}
	reply := proto.Clone(&f).(*flowpb.Flow)
	reply.IsReply = &wrapperspb.BoolValue{Value: true}
	unknown := proto.Clone(&f).(*flowpb.Flow)
	unknown.IsReply = nil
	policyDenied := proto.Clone(&f).(*flowpb.Flow)
	policyDenied.EventType = &flowpb.CiliumEventType{
		Type: monitorAPI.MessageTypePolicyVerdict,
	}
	policyDenied.IsReply = nil
	policyDenied.TrafficDirection = flowpb.TrafficDirection_EGRESS
	type args struct {
		f *flowpb.Flow
	}
	tests := []struct {
		name     string
		options  []Option
		args     args
		wantErr  bool
		expected string
	}{
		{
			name: "tabular",
			options: []Option{
				WithColor("never"),
				Writer(&buf),
			},
			args: args{
				f: &f,
			},
			wantErr: false,
			expected: `TIMESTAMP             SOURCE          DESTINATION    TYPE            VERDICT   SUMMARY
Jan  1 00:20:34.567   1.1.1.1:31793   2.2.2.2:8080   Policy denied   DROPPED   TCP Flags: SYN`,
		},
		{
			name: "tabular-with-node",
			options: []Option{
				WithColor("never"),
				WithNodeName(),
				Writer(&buf),
			},
			args: args{
				f: &f,
			},
			wantErr: false,
			expected: `TIMESTAMP             NODE   SOURCE          DESTINATION    TYPE            VERDICT   SUMMARY
Jan  1 00:20:34.567   k8s1   1.1.1.1:31793   2.2.2.2:8080   Policy denied   DROPPED   TCP Flags: SYN`,
		},
		{
			name: "tabular-terminal-escaped",
			options: []Option{
				WithColor("never"),
				Writer(&buf),
			},
			args: args{
				f: &kafkaUnescapedFlow,
			},
			wantErr: false,
			expected: `TIMESTAMP             SOURCE          DESTINATION    TYPE            VERDICT   SUMMARY
Jan  1 00:20:34.567   1.1.1.1:31793   2.2.2.2:8080   kafka-request   DROPPED   Kafka request 1234 correlation id 1 topic 'my-topic[^[30mblack[^[0m[^\r'`,
		},
		{
			name: "compact",
			options: []Option{
				Compact(),
				WithColor("never"),
				Writer(&buf),
			},
			args: args{
				f: &f,
			},
			wantErr: false,
			expected: "Jan  1 00:20:34.567: " +
				"1.1.1.1:31793 (health) -> 2.2.2.2:8080 (ID:12345) " +
				"Policy denied DROPPED (TCP Flags: SYN)\n",
		},
		{
			name: "compact-with-node",
			options: []Option{
				Compact(),
				WithColor("never"),
				WithNodeName(),
				Writer(&buf),
			},
			args: args{
				f: &f,
			},
			wantErr: false,
			expected: "Jan  1 00:20:34.567 [k8s1]: " +
				"1.1.1.1:31793 (health) -> 2.2.2.2:8080 (ID:12345) " +
				"Policy denied DROPPED (TCP Flags: SYN)\n",
		},
		{
			name: "compact-reply",
			options: []Option{
				Compact(),
				WithColor("never"),
				WithNodeName(),
				Writer(&buf),
			},
			args: args{
				f: reply,
			},
			wantErr: false,
			expected: "Jan  1 00:20:34.567 [k8s1]: " +
				"2.2.2.2:8080 (ID:12345) <- 1.1.1.1:31793 (health) " +
				"Policy denied DROPPED (TCP Flags: SYN)\n",
		},
		{
			name: "compact-policy-verdict-denied",
			options: []Option{
				Compact(),
				WithColor("never"),
				WithNodeName(),
				Writer(&buf),
			},
			args: args{
				f: policyDenied,
			},
			wantErr: false,
			expected: "Jan  1 00:20:34.567 [k8s1]: " +
				"1.1.1.1:31793 (health) <> 2.2.2.2:8080 (ID:12345) " +
				"policy-verdict:none EGRESS DENIED (TCP Flags: SYN)\n",
		},
		{
			name: "compact-direction-unknown",
			options: []Option{
				Compact(),
				WithColor("never"),
				WithNodeName(),
				Writer(&buf),
			},
			args: args{
				f: unknown,
			},
			wantErr: false,
			expected: "Jan  1 00:20:34.567 [k8s1]: " +
				"1.1.1.1:31793 (health) <> 2.2.2.2:8080 (ID:12345) " +
				"Policy denied DROPPED (TCP Flags: SYN)\n",
		},
		{
			name: "compact-terminal-escaped",
			options: []Option{
				Compact(),
				WithColor("never"),
				Writer(&buf),
			},
			args: args{
				f: &kafkaUnescapedFlow,
			},
			wantErr: false,
			expected: "Jan  1 00:20:34.567: " +
				"1.1.1.1:31793 (health) -> 2.2.2.2:8080 (ID:12345) " +
				"kafka-request DROPPED (Kafka request 1234 correlation id 1 topic 'my-topic[^[30mblack[^[0m[^\\r')\n",
		},
		{
			name: "compact-terminal-escaped-colored",
			options: []Option{
				Compact(),
				WithColor("always"),
				Writer(&buf),
			},
			args: args{
				f: &kafkaUnescapedFlow,
			},
			wantErr: false,
			expected: "Jan  1 00:20:34.567: " +
				"\x1b[36m1.1.1.1:\x1b[33m31793\x1b[0m\x1b[0m \x1b[35m(health)\x1b[0m -> \x1b[36m2.2.2.2:\x1b[33m8080\x1b[0m\x1b[0m \x1b[35m(ID:12345)\x1b[0m " +
				"kafka-request \x1b[31mDROPPED\x1b[0m (Kafka request 1234 correlation id 1 topic 'my-topic[^[30mblack[^[0m[^\\r')\n",
		},
		{
			name: "json",
			options: []Option{
				JSONLegacy(),
				WithColor("never"),
				Writer(&buf),
			},
			args: args{
				f: &f,
			},
			wantErr: false,
			expected: `{"time":"1970-01-01T00:20:34.567800Z",` +
				`"verdict":"DROPPED",` +
				`"IP":{"source":"1.1.1.1","destination":"2.2.2.2"},` +
				`"l4":{"TCP":{"source_port":31793,"destination_port":8080}},` +
				`"source":{"identity":4},"destination":{"identity":12345},` +
				`"Type":"L3_L4","node_name":"k8s1",` +
				`"event_type":{"type":1,"sub_type":133},` +
				`"is_reply":false,"Summary":"TCP Flags: SYN"}`,
		},
		{
			name: "jsonpb",
			options: []Option{
				JSONPB(),
				WithColor("never"),
				Writer(&buf),
			},
			args: args{
				f: &f,
			},
			wantErr: false,
			expected: `{"flow":{"time":"1970-01-01T00:20:34.567800Z",` +
				`"verdict":"DROPPED",` +
				`"IP":{"source":"1.1.1.1","destination":"2.2.2.2"},` +
				`"l4":{"TCP":{"source_port":31793,"destination_port":8080}},` +
				`"source":{"identity":4},"destination":{"identity":12345},` +
				`"Type":"L3_L4","node_name":"k8s1",` +
				`"event_type":{"type":1,"sub_type":133},` +
				`"is_reply":false,"Summary":"TCP Flags: SYN"}}`,
		},
		{
			name: "jsonpb-terminal-escaped",
			options: []Option{
				JSONPB(),
				WithColor("never"),
				Writer(&buf),
			},
			args: args{
				f: &kafkaUnescapedFlow,
			},
			wantErr: false,
			expected: `{"flow":{"time":"1970-01-01T00:20:34.567800Z",` +
				`"verdict":"DROPPED",` +
				`"IP":{"source":"1.1.1.1","destination":"2.2.2.2"},` +
				`"l4":{"TCP":{"source_port":31793,"destination_port":8080}},` +
				`"source":{"identity":4},"destination":{"identity":12345},` +
				`"Type":"L7","node_name":"k8s1",` +
				`"l7":{"type":"REQUEST","latency_ns":"10","kafka":{"api_key":"1234","correlation_id":1,"topic":"my-topic\u001b[30mblack\u001b[0m\u001b\r"}},` +
				`"event_type":{"type":1,"sub_type":133},` +
				`"is_reply":false,"Summary":"Kafka request 1234 correlation id 1 topic 'my-topic[^[30mblack[^[0m[^\\r'"}}`,
		},
		{
			name: "dict",
			options: []Option{
				Dict(),
				WithColor("never"),
				Writer(&buf),
			},
			args: args{
				f: &f,
			},
			wantErr: false,
			expected: `  TIMESTAMP: Jan  1 00:20:34.567
     SOURCE: 1.1.1.1:31793
DESTINATION: 2.2.2.2:8080
       TYPE: Policy denied
    VERDICT: DROPPED
    SUMMARY: TCP Flags: SYN`,
		},
		{
			name: "dict-with-node",
			options: []Option{
				Dict(),
				WithColor("never"),
				WithNodeName(),
				Writer(&buf),
			},
			args: args{
				f: &f,
			},
			wantErr: false,
			expected: `  TIMESTAMP: Jan  1 00:20:34.567
       NODE: k8s1
     SOURCE: 1.1.1.1:31793
DESTINATION: 2.2.2.2:8080
       TYPE: Policy denied
    VERDICT: DROPPED
    SUMMARY: TCP Flags: SYN`,
		},
		{
			name: "dict-terminal-escaped",
			options: []Option{
				Dict(),
				WithColor("never"),
				Writer(&buf),
			},
			args: args{
				f: &kafkaUnescapedFlow,
			},
			wantErr: false,
			expected: `  TIMESTAMP: Jan  1 00:20:34.567
     SOURCE: 1.1.1.1:31793
DESTINATION: 2.2.2.2:8080
       TYPE: kafka-request
    VERDICT: DROPPED
    SUMMARY: Kafka request 1234 correlation id 1 topic 'my-topic[^[30mblack[^[0m[^\r'`,
		},
	}
	for _, tt := range tests {
		buf.Reset()
		t.Run(tt.name, func(t *testing.T) {
			p := New(tt.options...)
			res := &observerpb.GetFlowsResponse{
				ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: tt.args.f},
			}
			// writes a node status event into the error stream
			if err := p.WriteProtoFlow(res); (err != nil) != tt.wantErr {
				t.Errorf("WriteProtoFlow() error = %v, wantErr %v", err, tt.wantErr)
			}
			require.NoError(t, p.Close())
			require.Equal(t, strings.TrimSpace(tt.expected), strings.TrimSpace(buf.String()))
		})
	}
}

func Test_getHostNames(t *testing.T) {
	type args struct {
		f *flowpb.Flow
	}
	type want struct {
		src, dst string
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "nil flow",
			args: args{},
			want: want{},
		}, {
			name: "nil ip",
			args: args{
				f: &flowpb.Flow{},
			},
			want: want{},
		}, {
			name: "valid ips",
			args: args{
				f: &flowpb.Flow{
					IP: &flowpb.IP{
						Source:      "1.1.1.1",
						Destination: "2.2.2.2",
					},
				},
			},
			want: want{
				src: "1.1.1.1",
				dst: "2.2.2.2",
			},
		}, {
			name: "valid ips/endpoints",
			args: args{
				f: &flowpb.Flow{
					IP: &flowpb.IP{
						Source:      "1.1.1.1",
						Destination: "2.2.2.2",
					},
					Source: &flowpb.Endpoint{
						Namespace: "srcns",
						PodName:   "srcpod",
					},
					Destination: &flowpb.Endpoint{
						Namespace: "dstns",
						PodName:   "dstpod",
					},
				},
			},
			want: want{
				src: "srcns/srcpod",
				dst: "dstns/dstpod",
			},
		}, {
			name: "valid tcp",
			args: args{
				f: &flowpb.Flow{
					IP: &flowpb.IP{
						Source:      "1.1.1.1",
						Destination: "2.2.2.2",
					},
					L4: &flowpb.Layer4{
						Protocol: &flowpb.Layer4_TCP{
							TCP: &flowpb.TCP{
								SourcePort:      55555,
								DestinationPort: 80,
							},
						},
					},
				},
			},
			want: want{
				src: "1.1.1.1:55555",
				dst: "2.2.2.2:80",
			},
		}, {
			name: "valid udp",
			args: args{
				f: &flowpb.Flow{
					IP: &flowpb.IP{
						Source:      "1.1.1.1",
						Destination: "2.2.2.2",
					},
					L4: &flowpb.Layer4{
						Protocol: &flowpb.Layer4_UDP{
							UDP: &flowpb.UDP{
								SourcePort:      55555,
								DestinationPort: 53,
							},
						},
					},
				},
			},
			want: want{
				src: "1.1.1.1:55555",
				dst: "2.2.2.2:53",
			},
		}, {
			name: "valid sctp",
			args: args{
				f: &flowpb.Flow{
					IP: &flowpb.IP{
						Source:      "1.1.1.1",
						Destination: "2.2.2.2",
					},
					L4: &flowpb.Layer4{
						Protocol: &flowpb.Layer4_SCTP{
							SCTP: &flowpb.SCTP{
								SourcePort:      55555,
								DestinationPort: 5060,
							},
						},
					},
				},
			},
			want: want{
				src: "1.1.1.1:55555",
				dst: "2.2.2.2:5060",
			},
		}, {
			name: "valid tcp service",
			args: args{
				f: &flowpb.Flow{
					IP: &flowpb.IP{
						Source:      "1.1.1.1",
						Destination: "2.2.2.2",
					},
					L4: &flowpb.Layer4{
						Protocol: &flowpb.Layer4_TCP{
							TCP: &flowpb.TCP{
								SourcePort:      55555,
								DestinationPort: 80,
							},
						},
					},
					SourceService: &flowpb.Service{
						Name:      "xwing",
						Namespace: "default",
					},
					DestinationService: &flowpb.Service{
						Name:      "tiefighter",
						Namespace: "deathstar",
					},
				},
			},
			want: want{
				src: "default/xwing:55555",
				dst: "deathstar/tiefighter:80",
			},
		}, {
			name: "valid udp service",
			args: args{
				f: &flowpb.Flow{
					IP: &flowpb.IP{
						Source:      "1.1.1.1",
						Destination: "2.2.2.2",
					},
					L4: &flowpb.Layer4{
						Protocol: &flowpb.Layer4_UDP{
							UDP: &flowpb.UDP{
								SourcePort:      55555,
								DestinationPort: 53,
							},
						},
					},
					SourceService: &flowpb.Service{
						Name:      "xwing",
						Namespace: "default",
					},
					DestinationService: &flowpb.Service{
						Name:      "tiefighter",
						Namespace: "deathstar",
					},
				},
			},
			want: want{
				src: "default/xwing:55555",
				dst: "deathstar/tiefighter:53",
			},
		}, {
			name: "dns",
			args: args{
				f: &flowpb.Flow{
					IP: &flowpb.IP{
						Source:      "1.1.1.1",
						Destination: "2.2.2.2",
					},
					L4: &flowpb.Layer4{
						Protocol: &flowpb.Layer4_TCP{
							TCP: &flowpb.TCP{
								SourcePort:      54321,
								DestinationPort: 65432,
							},
						},
					},
					SourceNames:      []string{"a"},
					DestinationNames: []string{"b"},
				},
			},
			want: want{
				src: "a:54321",
				dst: "b:65432",
			},
		},
		{
			name: "ethernet",
			args: args{
				f: &flowpb.Flow{
					Ethernet: &flowpb.Ethernet{
						Source:      "00:01:02:03:04:05",
						Destination: "06:07:08:09:0a:0b",
					},
				},
			},
			want: want{
				src: "00:01:02:03:04:05",
				dst: "06:07:08:09:0a:0b",
			},
		},
	}
	p := New(WithIPTranslation())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSrc, gotDst := p.GetHostNames(tt.args.f)
			if gotSrc != tt.want.src {
				t.Errorf("GetHostNames() got = %v, want %v", gotSrc, tt.want.src)
			}
			if gotDst != tt.want.dst {
				t.Errorf("GetHostNames() got1 = %v, want %v", gotDst, tt.want.dst)
			}
		})
	}
}

func Test_fmtTimestamp(t *testing.T) {
	type args struct {
		layout string
		t      *timestamppb.Timestamp
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "valid",
			args: args{
				layout: time.StampMilli,
				t: &timestamppb.Timestamp{
					Seconds: 0,
					Nanos:   0,
				},
			},
			want: "Jan  1 00:00:00.000",
		},
		{
			name: "valid non-zero",
			args: args{
				layout: time.StampMilli,
				t: &timestamppb.Timestamp{
					Seconds: 1530984600,
					Nanos:   123000000,
				},
			},
			want: "Jul  7 17:30:00.123",
		},
		{
			name: "invalid",
			args: args{
				layout: time.StampMilli,
				t: &timestamppb.Timestamp{
					Seconds: -1,
					Nanos:   -1,
				},
			},
			want: "N/A",
		},
		{
			name: "nil timestamp",
			args: args{},
			want: "N/A",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fmtTimestamp(tt.args.layout, tt.args.t); got != tt.want {
				t.Errorf("getTimestamp() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getFlowType(t *testing.T) {
	type args struct {
		f *flowpb.Flow
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "L7",
			args: args{
				f: &flowpb.Flow{
					L7: &flowpb.Layer7{
						Type: flowpb.L7FlowType_REQUEST,
					},
					EventType: &flowpb.CiliumEventType{
						Type: monitorAPI.MessageTypeAccessLog,
					},
				},
			},
			want: "l7-request",
		},
		{
			name: "HTTP",
			args: args{
				f: &flowpb.Flow{
					L7: &flowpb.Layer7{
						Type:   flowpb.L7FlowType_RESPONSE,
						Record: &flowpb.Layer7_Http{},
					},
					EventType: &flowpb.CiliumEventType{
						Type: monitorAPI.MessageTypeAccessLog,
					},
				},
			},
			want: "http-response",
		},
		{
			name: "Kafka",
			args: args{
				f: &flowpb.Flow{
					L7: &flowpb.Layer7{
						Type:   flowpb.L7FlowType_REQUEST,
						Record: &flowpb.Layer7_Kafka{},
					},
					EventType: &flowpb.CiliumEventType{
						Type: monitorAPI.MessageTypeAccessLog,
					},
				},
			},
			want: "kafka-request",
		},
		{
			name: "DNS",
			args: args{
				f: &flowpb.Flow{
					L7: &flowpb.Layer7{
						Type: flowpb.L7FlowType_REQUEST,
						Record: &flowpb.Layer7_Dns{
							Dns: &flowpb.DNS{ObservationSource: "proxy"},
						},
					},
					EventType: &flowpb.CiliumEventType{
						Type: monitorAPI.MessageTypeAccessLog,
					},
				},
			},
			want: "dns-request proxy",
		},
		{
			name: "L4",
			args: args{
				f: &flowpb.Flow{
					EventType: &flowpb.CiliumEventType{
						Type:    monitorAPI.MessageTypeTrace,
						SubType: monitorAPI.TraceToHost,
					},
				},
			},
			want: "to-host",
		},
		{
			name: "L4",
			args: args{
				f: &flowpb.Flow{
					Verdict: flowpb.Verdict_FORWARDED,
					EventType: &flowpb.CiliumEventType{
						Type: monitorAPI.MessageTypePolicyVerdict,
					},
					PolicyMatchType:  monitorAPI.PolicyMatchL3L4,
					TrafficDirection: flowpb.TrafficDirection_INGRESS,
				},
			},
			want: "policy-verdict:L3-L4 INGRESS",
		},
		{
			name: "L4",
			args: args{
				f: &flowpb.Flow{
					Verdict: flowpb.Verdict_DROPPED,
					EventType: &flowpb.CiliumEventType{
						Type: monitorAPI.MessageTypePolicyVerdict,
					},
					DropReason:       153,
					TrafficDirection: flowpb.TrafficDirection_INGRESS,
				},
			},
			want: "policy-verdict:none INGRESS",
		},
		{
			name: "SockLB pre-translate",
			args: args{
				f: &flowpb.Flow{
					Verdict: flowpb.Verdict_TRACED,
					EventType: &flowpb.CiliumEventType{
						Type: monitorAPI.MessageTypeTraceSock,
					},
					SockXlatePoint: flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_PRE_DIRECTION_FWD,
				},
			},
			want: "pre-xlate-fwd",
		},
		{
			name: "SockLB post-translate",
			args: args{
				f: &flowpb.Flow{
					Verdict: flowpb.Verdict_TRANSLATED,
					EventType: &flowpb.CiliumEventType{
						Type: monitorAPI.MessageTypeTraceSock,
					},
					SockXlatePoint: flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_POST_DIRECTION_FWD,
				},
			},
			want: "post-xlate-fwd",
		},
		{
			name: "Debug Capture",
			args: args{
				f: &flowpb.Flow{
					EventType: &flowpb.CiliumEventType{
						Type: monitorAPI.MessageTypeCapture,
					},
					DebugCapturePoint: flowpb.DebugCapturePoint_DBG_CAPTURE_FROM_LB,
				},
			},
			want: "DBG_CAPTURE_FROM_LB",
		},
		{
			name: "invalid",
			args: args{
				f: &flowpb.Flow{
					EventType: &flowpb.CiliumEventType{
						Type:    monitorAPI.MessageTypeTrace,
						SubType: 123, // invalid subtype
					},
				},
			},
			want: "123",
		},
		{
			name: "nil flow",
			args: args{},
			want: "UNKNOWN",
		},

		{
			name: "nil type",
			args: args{
				f: &flowpb.Flow{},
			},
			want: "UNKNOWN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetFlowType(tt.args.f); got != tt.want {
				t.Errorf("GetFlowType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHostname(t *testing.T) {
	p := New(WithIPTranslation())
	assert.Equal(t, "default/pod", p.Hostname("", "", "default", "pod", "", []string{}))
	assert.Equal(t, "default/pod", p.Hostname("", "", "default", "pod", "service", []string{}))
	assert.Equal(t, "default/service", p.Hostname("", "", "default", "", "service", []string{}))
	assert.Equal(t, "a,b", p.Hostname("", "", "", "", "", []string{"a", "b"}))
	p = New()
	assert.Equal(t, "1.1.1.1:80", p.Hostname("1.1.1.1", "80", "default", "pod", "", []string{}))
	assert.Equal(t, "1.1.1.1:80", p.Hostname("1.1.1.1", "80", "default", "pod", "service", []string{}))
	assert.Equal(t, "1.1.1.1", p.Hostname("1.1.1.1", "0", "default", "pod", "", []string{}))
	assert.Equal(t, "1.1.1.1", p.Hostname("1.1.1.1", "0", "default", "pod", "service", []string{}))
}

func TestPrinter_AgentEventDetails(t *testing.T) {
	startTS := timestamppb.New(time.Now())
	require.NoError(t, startTS.CheckValid())

	tests := []struct {
		name string
		ev   *flowpb.AgentEvent
		want string
	}{
		{
			name: "nil",
			want: "UNKNOWN",
		},
		{
			name: "empty",
			ev:   &flowpb.AgentEvent{},
			want: "UNKNOWN",
		},
		{
			name: "unknown without notification",
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_AGENT_EVENT_UNKNOWN,
			},
			want: "UNKNOWN",
		},
		{
			name: "agent start without notification",
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_AGENT_STARTED,
			},
			want: "UNKNOWN",
		},
		{
			name: "agent start with notification",
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_AGENT_STARTED,
				Notification: &flowpb.AgentEvent_AgentStart{
					AgentStart: &flowpb.TimeNotification{
						Time: startTS,
					},
				},
			},
			want: "start time: " + fmtTimestamp(time.StampMilli, startTS),
		},
		{
			name: "policy update",
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_POLICY_UPDATED,
				Notification: &flowpb.AgentEvent_PolicyUpdate{
					PolicyUpdate: &flowpb.PolicyUpdateNotification{
						Labels:    []string{"foo=bar", "baz=foo"},
						Revision:  1,
						RuleCount: 2,
					},
				},
			},
			want: "labels: [foo=bar,baz=foo], revision: 1, count: 2",
		},
		{
			name: "policy delete",
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_POLICY_DELETED,
				Notification: &flowpb.AgentEvent_PolicyUpdate{
					PolicyUpdate: &flowpb.PolicyUpdateNotification{
						Revision:  42,
						RuleCount: 1,
					},
				},
			},
			want: "labels: [], revision: 42, count: 1",
		},
		{
			name: "endpoint regenerate success",
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_ENDPOINT_REGENERATE_SUCCESS,
				Notification: &flowpb.AgentEvent_EndpointRegenerate{
					EndpointRegenerate: &flowpb.EndpointRegenNotification{
						Id:     42,
						Labels: []string{"baz=bar", "some=label"},
					},
				},
			},
			want: "id: 42, labels: [baz=bar,some=label]",
		},
		{
			name: "endpoint regenerate failure",
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_ENDPOINT_REGENERATE_FAILURE,
				Notification: &flowpb.AgentEvent_EndpointRegenerate{
					EndpointRegenerate: &flowpb.EndpointRegenNotification{
						Id:     42,
						Labels: []string{"baz=bar", "some=label"},
						Error:  "some error",
					},
				},
			},
			want: "id: 42, labels: [baz=bar,some=label], error: some error",
		},
		{
			name: "endpoint created",
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_ENDPOINT_CREATED,
				Notification: &flowpb.AgentEvent_EndpointUpdate{
					EndpointUpdate: &flowpb.EndpointUpdateNotification{
						Id:        1027,
						Namespace: "kube-system",
						PodName:   "cilium-xyz",
					},
				},
			},
			want: "id: 1027, namespace: kube-system, pod name: cilium-xyz",
		},
		{
			name: "ipcache upsert",
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_IPCACHE_UPSERTED,
				Notification: &flowpb.AgentEvent_IpcacheUpdate{
					IpcacheUpdate: &flowpb.IPCacheNotification{
						Cidr:     "10.1.2.3/32",
						Identity: 42,
						OldIdentity: &wrapperspb.UInt32Value{
							Value: 23,
						},
						HostIp:     "192.168.3.9",
						EncryptKey: 3,
					},
				},
			},
			want: "cidr: 10.1.2.3/32, identity: 42, old identity: 23, host ip: 192.168.3.9, encrypt key: 3",
		},
		{
			name: "ipcache delete",
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_IPCACHE_DELETED,
				Notification: &flowpb.AgentEvent_IpcacheUpdate{
					IpcacheUpdate: &flowpb.IPCacheNotification{
						Cidr:      "10.0.1.2/32",
						Identity:  42,
						OldHostIp: "192.168.1.23",
					},
				},
			},
			want: "cidr: 10.0.1.2/32, identity: 42, old host ip: 192.168.1.23, encrypt key: 0",
		},
		{
			name: "service upsert",
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_SERVICE_UPSERTED,
				Notification: &flowpb.AgentEvent_ServiceUpsert{
					ServiceUpsert: &flowpb.ServiceUpsertNotification{
						Id: 42,
						FrontendAddress: &flowpb.ServiceUpsertNotificationAddr{
							Ip:   "10.0.0.42",
							Port: 8008,
						},
						BackendAddresses: []*flowpb.ServiceUpsertNotificationAddr{
							{
								Ip:   "192.168.1.23",
								Port: 80,
							},
							{
								Ip:   "2001:db8:85a3:::8a2e:370:1337",
								Port: 8080,
							},
						},
						Type:          "foobar",
						TrafficPolicy: "pol1",
						Namespace:     "bar",
						Name:          "foo",
					},
				},
			},
			want: "id: 42, frontend: 10.0.0.42:8008, backends: [192.168.1.23:80,[2001:db8:85a3:::8a2e:370:1337]:8080], type: foobar, traffic policy: pol1, namespace: bar, name: foo",
		},
		{
			name: "service delete",
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_SERVICE_DELETED,
				Notification: &flowpb.AgentEvent_ServiceDelete{
					ServiceDelete: &flowpb.ServiceDeleteNotification{
						Id: 42,
					},
				},
			},
			want: "id: 42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAgentEventDetails(tt.ev, time.StampMilli); got != tt.want {
				t.Errorf("getAgentEventDetails()\ngot:  %v,\nwant: %v", got, tt.want)
			}
		})
	}

}
func TestPrinter_WriteProtoDebugEvent(t *testing.T) {
	buf := bytes.Buffer{}
	ts := &timestamppb.Timestamp{
		Seconds: 1234,
		Nanos:   567800000,
	}
	node := "k8s1"
	dbg := &flowpb.DebugEvent{
		Type: flowpb.DebugEventType_DBG_CT_VERDICT,
		Source: &flowpb.Endpoint{
			ID:        690,
			Identity:  1332,
			Namespace: "cilium-test",
			Labels: []string{
				"k8s:io.cilium.k8s.policy.cluster=default",
				"k8s:io.cilium.k8s.policy.serviceaccount=default",
				"k8s:io.kubernetes.pod.namespace=cilium-test",
				"k8s:name=pod-to-a-denied-cnp",
			},
			PodName: "pod-to-a-denied-cnp-75cb89dfd-vqhd9",
		},
		Hash:    wrapperspb.UInt32(180354257),
		Arg1:    wrapperspb.UInt32(0),
		Arg2:    wrapperspb.UInt32(0),
		Arg3:    wrapperspb.UInt32(0),
		Message: "CT verdict: New, revnat=0",
		Cpu:     wrapperspb.Int32(1),
	}
	type args struct {
		dbg  *flowpb.DebugEvent
		ts   *timestamppb.Timestamp
		node string
	}
	tests := []struct {
		name     string
		options  []Option
		args     args
		wantErr  bool
		expected string
	}{
		{
			name: "tabular",
			options: []Option{
				Writer(&buf),
			},
			args: args{
				dbg:  dbg,
				node: node,
				ts:   ts,
			},
			wantErr: false,
			expected: `TIMESTAMP             FROM                                                           TYPE             CPU/MARK       MESSAGE
Jan  1 00:20:34.567   cilium-test/pod-to-a-denied-cnp-75cb89dfd-vqhd9 (ID: 690)      DBG_CT_VERDICT   01 0xabffcd1   CT verdict: New, revnat=0`,
		},
		{
			name: "tabular-with-node",
			options: []Option{
				WithNodeName(),
				Writer(&buf),
			},
			args: args{
				dbg:  dbg,
				node: node,
				ts:   ts,
			},
			wantErr: false,
			expected: `TIMESTAMP             NODE   FROM                                                           TYPE             CPU/MARK       MESSAGE
Jan  1 00:20:34.567   k8s1   cilium-test/pod-to-a-denied-cnp-75cb89dfd-vqhd9 (ID: 690)      DBG_CT_VERDICT   01 0xabffcd1   CT verdict: New, revnat=0`,
		},
		{
			name: "compact",
			options: []Option{
				Compact(),
				Writer(&buf),
			},
			args: args{
				dbg:  dbg,
				node: node,
				ts:   ts,
			},
			wantErr:  false,
			expected: "Jan  1 00:20:34.567: cilium-test/pod-to-a-denied-cnp-75cb89dfd-vqhd9 (ID: 690) DBG_CT_VERDICT MARK: 0xabffcd1 CPU: 01 (CT verdict: New, revnat=0)\n",
		},
		{
			name: "compact-with-node",
			options: []Option{
				Compact(),
				WithNodeName(),
				Writer(&buf),
			},
			args: args{
				dbg:  dbg,
				node: node,
				ts:   ts,
			},
			wantErr:  false,
			expected: "Jan  1 00:20:34.567 [k8s1]: cilium-test/pod-to-a-denied-cnp-75cb89dfd-vqhd9 (ID: 690) DBG_CT_VERDICT MARK: 0xabffcd1 CPU: 01 (CT verdict: New, revnat=0)\n",
		},
		{
			name: "json",
			options: []Option{
				JSONPB(),
				Writer(&buf),
			},
			args: args{
				dbg:  dbg,
				node: node,
				ts:   ts,
			},
			wantErr: false,
			expected: `{"debug_event":{"type":"DBG_CT_VERDICT","source":{"ID":690,"identity":1332,"namespace":"cilium-test","labels":` +
				`["k8s:io.cilium.k8s.policy.cluster=default","k8s:io.cilium.k8s.policy.serviceaccount=default",` +
				`"k8s:io.kubernetes.pod.namespace=cilium-test","k8s:name=pod-to-a-denied-cnp"],` +
				`"pod_name":"pod-to-a-denied-cnp-75cb89dfd-vqhd9"},` +
				`"hash":180354257,"arg1":0,"arg2":0,"arg3":0,"message":"CT verdict: New, revnat=0","cpu":1},` +
				`"node_name":"k8s1","time":"1970-01-01T00:20:34.567800Z"}`,
		},
		{
			name: "jsonpb",
			options: []Option{
				JSONPB(),
				Writer(&buf),
			},
			args: args{
				dbg:  dbg,
				node: node,
				ts:   ts,
			},
			wantErr: false,
			expected: `{"debug_event":{"type":"DBG_CT_VERDICT",` +
				`"source":{"ID":690,"identity":1332,"namespace":"cilium-test",` +
				`"labels":["k8s:io.cilium.k8s.policy.cluster=default","k8s:io.cilium.k8s.policy.serviceaccount=default",` +
				`"k8s:io.kubernetes.pod.namespace=cilium-test","k8s:name=pod-to-a-denied-cnp"],` +
				`"pod_name":"pod-to-a-denied-cnp-75cb89dfd-vqhd9"},` +
				`"hash":180354257,"arg1":0,"arg2":0,"arg3":0,"message":"CT verdict: New, revnat=0","cpu":1},` +
				`"node_name":"k8s1","time":"1970-01-01T00:20:34.567800Z"}`,
		},
		{
			name: "dict",
			options: []Option{
				Dict(),
				Writer(&buf),
			},
			args: args{
				dbg:  dbg,
				node: node,
				ts:   ts,
			},
			wantErr: false,
			expected: `  TIMESTAMP: Jan  1 00:20:34.567
       TYPE: DBG_CT_VERDICT
       FROM: cilium-test/pod-to-a-denied-cnp-75cb89dfd-vqhd9 (ID: 690)
       MARK: 0xabffcd1
        CPU: 01
    MESSAGE: CT verdict: New, revnat=0`,
		},
		{
			name: "dict-with-node",
			options: []Option{
				Dict(),
				WithNodeName(),
				Writer(&buf),
			},
			args: args{
				dbg:  dbg,
				node: node,
				ts:   ts,
			},
			wantErr: false,
			expected: `  TIMESTAMP: Jan  1 00:20:34.567
       NODE: k8s1
       TYPE: DBG_CT_VERDICT
       FROM: cilium-test/pod-to-a-denied-cnp-75cb89dfd-vqhd9 (ID: 690)
       MARK: 0xabffcd1
        CPU: 01
    MESSAGE: CT verdict: New, revnat=0`,
		},
	}

	for _, tt := range tests {
		buf.Reset()
		t.Run(tt.name, func(t *testing.T) {
			p := New(tt.options...)
			res := &observerpb.GetDebugEventsResponse{
				DebugEvent: tt.args.dbg,
				NodeName:   tt.args.node,
				Time:       tt.args.ts,
			}
			if err := p.WriteProtoDebugEvent(res); (err != nil) != tt.wantErr {
				t.Errorf("WriteProtoDebugEvent() error = %v, wantErr %v", err, tt.wantErr)
			}
			require.NoError(t, p.Close())
			require.Equal(t, strings.TrimSpace(tt.expected), strings.TrimSpace(buf.String()))
		})
	}
}

func TestPrinter_WriteServerStatusResponse(t *testing.T) {
	buf := bytes.Buffer{}
	ss := &observerpb.ServerStatusResponse{
		NumFlows:  2031,
		MaxFlows:  4095,
		SeenFlows: 2348885,
		FlowsRate: 23.456,
		UptimeNs:  301515181665,
		Version:   "cilium v1.15.0+g4145278",
	}
	sso := &observerpb.ServerStatusResponse{
		NumFlows:  2031,
		MaxFlows:  4095,
		SeenFlows: 2348885,
		UptimeNs:  301515181665,
		Version:   "cilium v1.10.3+g4145278",
	}
	ssn := &observerpb.ServerStatusResponse{
		NumFlows:            2771,
		MaxFlows:            8190,
		SeenFlows:           2771,
		FlowsRate:           23.456,
		UptimeNs:            301515181665,
		Version:             "hubble-relay v1.15.0+g4145278",
		NumConnectedNodes:   &wrapperspb.UInt32Value{Value: 2},
		NumUnavailableNodes: &wrapperspb.UInt32Value{Value: 0},
	}
	type args struct {
		ss *observerpb.ServerStatusResponse
	}
	tests := []struct {
		name     string
		options  []Option
		args     args
		wantErr  bool
		expected string
	}{
		{
			name: "tabular",
			options: []Option{
				WithColor("never"),
				Writer(&buf),
			},
			args:    args{ss},
			wantErr: false,
			expected: `
NUM FLOWS   MAX FLOWS   SEEN FLOWS   FLOWS PER SECOND   UPTIME           NUM CONNECTED NODES   NUM UNAVAILABLE NODES   VERSION
2,031       4,095       2,348,885    23.46              5m1.515181665s   N/A                   N/A                     cilium v1.15.0+g4145278`,
		}, {
			name: "tabular-with-nodes",
			options: []Option{
				WithColor("never"),
				Writer(&buf),
			},
			args:    args{ssn},
			wantErr: false,
			expected: `
NUM FLOWS   MAX FLOWS   SEEN FLOWS   FLOWS PER SECOND   UPTIME           NUM CONNECTED NODES   NUM UNAVAILABLE NODES   VERSION
2,771       8,190       2,771        23.46              5m1.515181665s   2                     0                       hubble-relay v1.15.0+g4145278`,
		}, {
			name: "tabular-without-flow-rate",
			options: []Option{
				WithColor("never"),
				Writer(&buf),
			},
			args:    args{sso},
			wantErr: false,
			expected: `
NUM FLOWS   MAX FLOWS   SEEN FLOWS   FLOWS PER SECOND   UPTIME           NUM CONNECTED NODES   NUM UNAVAILABLE NODES   VERSION
2,031       4,095       2,348,885    N/A                5m1.515181665s   N/A                   N/A                     cilium v1.10.3+g4145278`,
		}, {
			name: "compact",
			options: []Option{
				Compact(),
				WithColor("never"),
				Writer(&buf),
			},
			args:    args{ss},
			wantErr: false,
			expected: `
Current/Max Flows: 2,031/4,095 (49.60%)
Flows/s: 23.46`,
		}, {
			name: "compact-with-nodes",
			options: []Option{
				Compact(),
				WithColor("never"),
				Writer(&buf),
			},
			args:    args{ssn},
			wantErr: false,
			expected: `
Current/Max Flows: 2,771/8,190 (33.83%)
Flows/s: 23.46
Connected Nodes: 2/2`,
		}, {
			name: "compact-without-flow-rate",
			options: []Option{
				Compact(),
				WithColor("never"),
				Writer(&buf),
			},
			args:    args{sso},
			wantErr: false,
			expected: `
Current/Max Flows: 2,031/4,095 (49.60%)
Flows/s: 7790.27`,
		}, {
			name: "json",
			options: []Option{
				JSONPB(),
				WithColor("never"),
				Writer(&buf),
			},
			args:     args{ss},
			wantErr:  false,
			expected: `{"num_flows":"2031","max_flows":"4095","seen_flows":"2348885","uptime_ns":"301515181665","version":"cilium v1.15.0+g4145278","flows_rate":23.456}`,
		}, {
			name: "json-with-nodes",
			options: []Option{
				JSONPB(),
				WithColor("never"),
				Writer(&buf),
			},
			args:     args{ssn},
			wantErr:  false,
			expected: `{"num_flows":"2771","max_flows":"8190","seen_flows":"2771","uptime_ns":"301515181665","num_connected_nodes":2,"num_unavailable_nodes":0,"version":"hubble-relay v1.15.0+g4145278","flows_rate":23.456}`,
		}, {
			name: "json-without-flow-rate",
			options: []Option{
				JSONPB(),
				WithColor("never"),
				Writer(&buf),
			},
			args:     args{sso},
			wantErr:  false,
			expected: `{"num_flows":"2031","max_flows":"4095","seen_flows":"2348885","uptime_ns":"301515181665","version":"cilium v1.10.3+g4145278"}`,
		}, {
			name: "jsonpb",
			options: []Option{
				JSONPB(),
				WithColor("never"),
				Writer(&buf),
			},
			args:     args{ss},
			wantErr:  false,
			expected: `{"num_flows":"2031","max_flows":"4095","seen_flows":"2348885","uptime_ns":"301515181665","version":"cilium v1.15.0+g4145278","flows_rate":23.456}`,
		}, {
			name: "dict",
			options: []Option{
				Dict(),
				WithColor("never"),
				Writer(&buf),
			},
			args:    args{ss},
			wantErr: false,
			expected: `
          NUM FLOWS: 2,031
          MAX FLOWS: 4,095
         SEEN FLOWS: 2,348,885
   FLOWS PER SECOND: 23.46
             UPTIME: 5m1.515181665s
NUM CONNECTED NODES: N/A
 NUM UNAVAIL. NODES: N/A
            VERSION: cilium v1.15.0+g4145278`,
		}, {
			name: "dict-with-nodes",
			options: []Option{
				Dict(),
				WithColor("never"),
				Writer(&buf),
			},
			args:    args{ssn},
			wantErr: false,
			expected: `
          NUM FLOWS: 2,771
          MAX FLOWS: 8,190
         SEEN FLOWS: 2,771
   FLOWS PER SECOND: 23.46
             UPTIME: 5m1.515181665s
NUM CONNECTED NODES: 2
 NUM UNAVAIL. NODES: 0
            VERSION: hubble-relay v1.15.0+g4145278`,
		}, {
			name: "dict",
			options: []Option{
				Dict(),
				WithColor("never"),
				Writer(&buf),
			},
			args:    args{sso},
			wantErr: false,
			expected: `
          NUM FLOWS: 2,031
          MAX FLOWS: 4,095
         SEEN FLOWS: 2,348,885
   FLOWS PER SECOND: N/A
             UPTIME: 5m1.515181665s
NUM CONNECTED NODES: N/A
 NUM UNAVAIL. NODES: N/A
            VERSION: cilium v1.10.3+g4145278`,
		},
	}
	for _, tt := range tests {
		buf.Reset()
		t.Run(tt.name, func(t *testing.T) {
			p := New(tt.options...)
			if err := p.WriteServerStatusResponse(tt.args.ss); (err != nil) != tt.wantErr {
				t.Errorf("WriteServerStatusResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			require.NoError(t, p.Close())
			require.Equal(t, strings.TrimSpace(tt.expected), strings.TrimSpace(buf.String()))
		})
	}
}

func TestPrinter_WriteLostEventsResponse(t *testing.T) {
	buf := bytes.Buffer{}
	gfr := &observerpb.GetFlowsResponse{
		ResponseTypes: &observerpb.GetFlowsResponse_LostEvents{
			LostEvents: &observerpb.LostEvent{
				Source:        observerpb.LostEventSource_HUBBLE_RING_BUFFER,
				NumEventsLost: 1,
				Cpu:           wrapperspb.Int32(5),
			},
		},
	}
	type args struct {
		le *observerpb.GetFlowsResponse
	}
	tests := []struct {
		name     string
		options  []Option
		args     args
		wantErr  bool
		expected string
	}{
		{
			name: "tabular",
			options: []Option{
				WithColor("never"),
				Writer(&buf),
			},
			args:    args{gfr},
			wantErr: false,
			expected: `
TIMESTAMP   SOURCE               DESTINATION   TYPE          VERDICT   SUMMARY
            HUBBLE_RING_BUFFER                 EVENTS LOST             CPU(5) - 1`,
		}, {
			name: "compact",
			options: []Option{
				Compact(),
				WithColor("never"),
				Writer(&buf),
			},
			args:    args{gfr},
			wantErr: false,
			expected: `
EVENTS LOST: HUBBLE_RING_BUFFER CPU(5) 1`,
		}, {
			name: "json",
			options: []Option{
				JSONPB(),
				WithColor("never"),
				Writer(&buf),
			},
			args:     args{gfr},
			wantErr:  false,
			expected: `{"lost_events":{"source":"HUBBLE_RING_BUFFER","num_events_lost":"1","cpu":5}}`,
		}, {
			name: "jsonpb",
			options: []Option{
				JSONPB(),
				WithColor("never"),
				Writer(&buf),
			},
			args:     args{gfr},
			wantErr:  false,
			expected: `{"lost_events":{"source":"HUBBLE_RING_BUFFER","num_events_lost":"1","cpu":5}}`,
		}, {
			name: "dict",
			options: []Option{
				Dict(),
				WithColor("never"),
				Writer(&buf),
			},
			args:    args{gfr},
			wantErr: false,
			expected: `
  TIMESTAMP: 
     SOURCE: HUBBLE_RING_BUFFER
       TYPE: EVENTS LOST
    VERDICT: 
    SUMMARY: CPU(5) - 1`,
		},
	}
	for _, tt := range tests {
		buf.Reset()
		t.Run(tt.name, func(t *testing.T) {
			p := New(tt.options...)
			if err := p.WriteLostEvent(tt.args.le); (err != nil) != tt.wantErr {
				t.Errorf("WriteServerStatusResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			require.NoError(t, p.Close())
			require.Equal(t, strings.TrimSpace(tt.expected), strings.TrimSpace(buf.String()))
		})
	}
}

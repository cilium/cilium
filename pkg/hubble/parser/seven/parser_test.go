// Copyright 2019 Authors of Hubble
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

package seven

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var log *logrus.Logger

var (
	fakeTimestamp = "2006-01-02T15:04:05.999999999Z"
	fakeNodeInfo  = accesslog.NodeAddressInfo{
		IPv4: "192.168.1.100",
		IPv6: " fd01::a",
	}
	fakeSourceEndpoint = accesslog.EndpointInfo{
		ID:       1234,
		IPv4:     "10.16.32.10",
		IPv6:     "f00d::a10:0:0:abcd",
		Identity: 9876,
		Labels:   []string{"k1=v1", "k2=v2"},
	}
	fakeDestinationEndpoint = accesslog.EndpointInfo{
		ID:       4321,
		IPv4:     "10.16.32.20",
		IPv6:     "f00d::a10:0:0:1234",
		Port:     80,
		Identity: 6789,
		Labels:   []string{"k3=v3", "k4=v4"},
	}
)

func init() {
	log = logrus.New()
	log.SetOutput(io.Discard)
}

func TestDecodeL7HTTPRecord(t *testing.T) {
	requestPath, err := url.Parse("http://myhost/some/path")
	require.NoError(t, err)
	lr := &accesslog.LogRecord{
		Type:                accesslog.TypeResponse,
		Timestamp:           fakeTimestamp,
		NodeAddressInfo:     fakeNodeInfo,
		ObservationPoint:    accesslog.Ingress,
		SourceEndpoint:      fakeSourceEndpoint,
		DestinationEndpoint: fakeDestinationEndpoint,
		IPVersion:           accesslog.VersionIPv4,
		Verdict:             accesslog.VerdictForwarded,
		TransportProtocol:   accesslog.TransportProtocol(u8proto.TCP),
		ServiceInfo:         nil,
		DropReason:          nil,
		HTTP: &accesslog.LogRecordHTTP{
			Code:     404,
			Method:   "POST",
			URL:      requestPath,
			Protocol: "HTTP/1.1",
			Headers: map[string][]string{
				"Host": {"myhost"},
			},
		},
	}
	lr.SourceEndpoint.Port = 56789
	lr.DestinationEndpoint.Port = 80

	dnsGetter := &testutils.FakeFQDNCache{
		OnGetNamesOf: func(epID uint32, ip net.IP) (names []string) {
			ipStr := ip.String()
			switch {
			case epID == uint32(fakeSourceEndpoint.ID) && ipStr == fakeDestinationEndpoint.IPv4:
				return []string{"endpoint-1234"}
			case epID == uint32(fakeDestinationEndpoint.ID) && ipStr == fakeSourceEndpoint.IPv4:
				return []string{"endpoint-4321"}
			}
			return nil
		},
	}
	IPGetter := &testutils.FakeIPGetter{
		OnGetK8sMetadata: func(ip net.IP) *ipcache.K8sMetadata {
			if ip.String() == fakeDestinationEndpoint.IPv4 {
				return &ipcache.K8sMetadata{
					Namespace: "default",
					PodName:   "pod-1234",
				}
			}
			return nil
		},
	}
	serviceGetter := &testutils.FakeServiceGetter{
		OnGetServiceByAddr: func(ip net.IP, port uint16) (service pb.Service, ok bool) {
			if ip.Equal(net.ParseIP(fakeDestinationEndpoint.IPv4)) && (port == fakeDestinationEndpoint.Port) {
				return pb.Service{
					Name:      "service-1234",
					Namespace: "default",
				}, true
			}
			return
		},
	}

	parser, err := New(log, dnsGetter, IPGetter, serviceGetter)
	require.NoError(t, err)

	f := &pb.Flow{}
	err = parser.Decode(lr, f)
	require.NoError(t, err)

	assert.Equal(t, fakeSourceEndpoint.IPv4, f.GetIP().GetDestination())
	assert.Equal(t, uint32(56789), f.GetL4().GetTCP().GetDestinationPort())
	assert.Equal(t, []string{"endpoint-4321"}, f.GetDestinationNames())
	assert.Equal(t, fakeSourceEndpoint.Labels, f.GetDestination().GetLabels())
	assert.Equal(t, "", f.GetDestination().GetNamespace())
	assert.Equal(t, "", f.GetDestination().GetPodName())
	assert.Equal(t, "", f.GetDestinationService().GetNamespace())
	assert.Equal(t, "", f.GetDestinationService().GetName())

	assert.Equal(t, fakeDestinationEndpoint.IPv4, f.GetIP().GetSource())
	assert.Equal(t, uint32(80), f.GetL4().GetTCP().GetSourcePort())
	assert.Equal(t, []string{"endpoint-1234"}, f.GetSourceNames())
	assert.Equal(t, fakeDestinationEndpoint.Labels, f.GetSource().GetLabels())
	assert.Equal(t, "default", f.GetSource().GetNamespace())
	assert.Equal(t, "pod-1234", f.GetSource().GetPodName())
	assert.Equal(t, "default", f.GetSourceService().GetNamespace())
	assert.Equal(t, "service-1234", f.GetSourceService().GetName())

	assert.Equal(t, pb.Verdict_FORWARDED, f.GetVerdict())

	assert.Equal(t, &pb.HTTP{
		Code:     404,
		Method:   "POST",
		Url:      "http://myhost/some/path",
		Protocol: "HTTP/1.1",
		Headers:  []*pb.HTTPHeader{{Key: "Host", Value: "myhost"}},
	}, f.GetL7().GetHttp())
}

func TestDecodeL7DNSRecord(t *testing.T) {
	lr := &accesslog.LogRecord{
		Type:                accesslog.TypeResponse,
		Timestamp:           fakeTimestamp,
		NodeAddressInfo:     fakeNodeInfo,
		ObservationPoint:    accesslog.Ingress,
		SourceEndpoint:      fakeSourceEndpoint,
		DestinationEndpoint: fakeDestinationEndpoint,
		IPVersion:           accesslog.VersionIPV6,
		Verdict:             accesslog.VerdictForwarded,
		TransportProtocol:   accesslog.TransportProtocol(u8proto.UDP),
		ServiceInfo:         nil,
		DropReason:          nil,
		DNS: &accesslog.LogRecordDNS{
			Query:             "deathstar.empire.svc.cluster.local.",
			IPs:               []net.IP{net.ParseIP("1.2.3.4")},
			TTL:               5,
			ObservationSource: accesslog.DNSSourceProxy,
			RCode:             0,
			QTypes:            []uint16{1},
			AnswerTypes:       []uint16{1},
		},
	}
	lr.SourceEndpoint.Port = 56789
	lr.DestinationEndpoint.Port = 53

	dnsGetter := &testutils.NoopDNSGetter
	ipGetter := &testutils.NoopIPGetter
	serviceGetter := &testutils.NoopServiceGetter

	parser, err := New(log, dnsGetter, ipGetter, serviceGetter)
	require.NoError(t, err)

	f := &pb.Flow{}
	err = parser.Decode(lr, f)
	require.NoError(t, err)

	ts := f.GetTime().AsTime()
	assert.Equal(t, fakeTimestamp, ts.Format(time.RFC3339Nano))

	assert.Equal(t, fakeSourceEndpoint.IPv6, f.GetIP().GetDestination())
	assert.Equal(t, uint32(56789), f.GetL4().GetUDP().GetDestinationPort())
	assert.Equal(t, []string(nil), f.GetDestinationNames())
	assert.Equal(t, fakeSourceEndpoint.Labels, f.GetDestination().GetLabels())
	assert.Equal(t, "", f.GetDestination().GetNamespace())
	assert.Equal(t, "", f.GetDestination().GetPodName())
	assert.Equal(t, "", f.GetDestinationService().GetNamespace())
	assert.Equal(t, "", f.GetDestinationService().GetName())

	assert.Equal(t, fakeDestinationEndpoint.IPv6, f.GetIP().GetSource())
	assert.Equal(t, uint32(53), f.GetL4().GetUDP().GetSourcePort())
	assert.Equal(t, []string(nil), f.GetSourceNames())
	assert.Equal(t, fakeDestinationEndpoint.Labels, f.GetSource().GetLabels())
	assert.Equal(t, "", f.GetSource().GetNamespace())
	assert.Equal(t, "", f.GetSource().GetPodName())
	assert.Equal(t, "", f.GetSourceService().GetNamespace())
	assert.Equal(t, "", f.GetSourceService().GetName())

	assert.Equal(t, pb.Verdict_FORWARDED, f.GetVerdict())

	assert.Equal(t, &pb.DNS{
		Query:             "deathstar.empire.svc.cluster.local.",
		Ips:               []string{"1.2.3.4"},
		Ttl:               5,
		ObservationSource: string(accesslog.DNSSourceProxy),
		Rcode:             0,
		Qtypes:            []string{"A"},
		Rrtypes:           []string{"A"},
	}, f.GetL7().GetDns())
}

func BenchmarkL7Decode(b *testing.B) {
	requestPath, err := url.Parse("http://myhost/some/path")
	require.NoError(b, err)
	lr := &accesslog.LogRecord{
		Type:                accesslog.TypeResponse,
		Timestamp:           fakeTimestamp,
		NodeAddressInfo:     fakeNodeInfo,
		ObservationPoint:    accesslog.Ingress,
		SourceEndpoint:      fakeSourceEndpoint,
		DestinationEndpoint: fakeDestinationEndpoint,
		IPVersion:           accesslog.VersionIPv4,
		Verdict:             accesslog.VerdictForwarded,
		TransportProtocol:   accesslog.TransportProtocol(u8proto.TCP),
		ServiceInfo:         nil,
		DropReason:          nil,
		HTTP: &accesslog.LogRecordHTTP{
			Code:     404,
			Method:   "POST",
			URL:      requestPath,
			Protocol: "HTTP/1.1",
			Headers: map[string][]string{
				"Host": {"myhost"},
			},
		},
	}
	lr.SourceEndpoint.Port = 56789
	lr.DestinationEndpoint.Port = 80

	dnsGetter := &testutils.NoopDNSGetter
	ipGetter := &testutils.NoopIPGetter
	serviceGetter := &testutils.NoopServiceGetter

	parser, err := New(log, dnsGetter, ipGetter, serviceGetter)
	require.NoError(b, err)

	f := &pb.Flow{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parser.Decode(lr, f)
	}
}

func TestDecodeResponseTime(t *testing.T) {
	requestID := "req-id"
	headers := http.Header{}
	headers.Add("X-Request-Id", requestID)
	httpRecord := &accesslog.LogRecordHTTP{
		Code:     200,
		Headers:  headers,
		Method:   "GET",
		Protocol: "HTTP/1.1",
		URL: &url.URL{
			Scheme: "http",
			Host:   "example.com",
			Path:   "/",
		},
	}
	requestTimestamp := time.Unix(0, 0).Format(time.RFC3339Nano)
	responseTimestamp := time.Unix(1, 0).Format(time.RFC3339Nano)

	parser, err := New(log, nil, nil, nil)
	require.NoError(t, err)

	request := &accesslog.LogRecord{
		Type:      accesslog.TypeRequest,
		Timestamp: requestTimestamp,
		HTTP:      httpRecord,
	}

	response := &accesslog.LogRecord{
		Type:      accesslog.TypeResponse,
		Timestamp: responseTimestamp,
		HTTP:      httpRecord,
	}

	f := &pb.Flow{}
	err = parser.Decode(request, f)
	require.NoError(t, err)
	_, ok := parser.cache.Get(requestID)
	assert.True(t, ok, "request id should be in the cache")

	f.Reset()
	err = parser.Decode(response, f)
	require.NoError(t, err)
	assert.Equal(t, 1*time.Second, time.Duration(f.GetL7().GetLatencyNs()))
	_, ok = parser.cache.Get(requestID)
	assert.False(t, ok, "request id should not be in the cache")

	// it should handle the case where the request id is not in the cache for response type.
	f = &pb.Flow{}
	err = parser.Decode(response, f)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), f.GetL7().GetLatencyNs())
	_, ok = parser.cache.Get(requestID)
	assert.False(t, ok, "request id should not be in the cache")
}

func Test_decodeKafka(t *testing.T) {
	type args struct {
		flowType accesslog.FlowType
		kafka    *accesslog.LogRecordKafka
	}
	tests := []struct {
		name string
		args args
		want *pb.Layer7_Kafka
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
			want: &pb.Layer7_Kafka{
				Kafka: &pb.Kafka{
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
			want: &pb.Layer7_Kafka{
				Kafka: &pb.Kafka{
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
			want: &pb.Layer7_Kafka{
				Kafka: &pb.Kafka{
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
		flow *pb.Flow
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
				flow: &pb.Flow{
					L7: &pb.Layer7{
						Type: pb.L7FlowType_REQUEST,
						Record: &pb.Layer7_Kafka{
							Kafka: &pb.Kafka{
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
				flow: &pb.Flow{
					L7: &pb.Layer7{
						Type: pb.L7FlowType_RESPONSE,
						Record: &pb.Layer7_Kafka{
							Kafka: &pb.Kafka{
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

func Test_decodeVerdict(t *testing.T) {
	assert.Equal(t, pb.Verdict_FORWARDED, decodeVerdict(accesslog.VerdictForwarded))
	assert.Equal(t, pb.Verdict_DROPPED, decodeVerdict(accesslog.VerdictDenied))
	assert.Equal(t, pb.Verdict_ERROR, decodeVerdict(accesslog.VerdictError))
	assert.Equal(t, pb.Verdict_REDIRECTED, decodeVerdict(accesslog.VerdictRedirected))
	assert.Equal(t, pb.Verdict_VERDICT_UNKNOWN, decodeVerdict("bad"))
}

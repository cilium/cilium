// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func Test_protoToL7(t *testing.T) {
	uu := map[string]struct {
		in *flow.Layer7
		e  Layer7
	}{
		"empty": {},

		"http": {
			in: &flow.Layer7{
				Type:      flow.L7FlowType_REQUEST,
				LatencyNs: 5,
				Record: &flow.Layer7_Http{
					Http: &flow.HTTP{
						Code:     200,
						Method:   "GET",
						Url:      "/index.html",
						Protocol: "http",
						Headers: []*flow.HTTPHeader{
							{Key: "a", Value: "b"},
							{Key: "b", Value: "c"},
						},
					},
				},
			},
			e: Layer7{
				Type:      flow.L7FlowType_REQUEST,
				LatencyNs: 5,
				HTTP: HTTP{
					Code:     200,
					Method:   "GET",
					URL:      "/index.html",
					Protocol: "http",
					Headers: []HTTPHeader{
						{Key: "a", Value: "b"},
						{Key: "b", Value: "c"},
					},
				},
			},
		},

		"dns": {
			in: &flow.Layer7{
				Type:      flow.L7FlowType_RESPONSE,
				LatencyNs: 10,
				Record: &flow.Layer7_Dns{
					Dns: &flow.DNS{
						Query:             "example.com",
						Ips:               []string{"1.2.3.4"},
						Ttl:               300,
						Cnames:            []string{"a", "b", "c"},
						ObservationSource: "blee",
						Rcode:             100,
						Qtypes:            []string{"A", "AAAA"},
						Rrtypes:           []string{"x", "z"},
					},
				},
			},
			e: Layer7{
				Type:      flow.L7FlowType_RESPONSE,
				LatencyNs: 10,
				DNS: DNS{
					Query:             "example.com",
					Ips:               []string{"1.2.3.4"},
					TTL:               300,
					CNames:            []string{"a", "b", "c"},
					ObservationSource: "blee",
					RCode:             100,
					Qtypes:            []string{"A", "AAAA"},
					Rtypes:            []string{"x", "z"},
				},
			},
		},

		"kafka": {
			in: &flow.Layer7{
				Type:      flow.L7FlowType_REQUEST,
				LatencyNs: 15,
				Record: &flow.Layer7_Kafka{
					Kafka: &flow.Kafka{
						ErrorCode:     1,
						ApiVersion:    100,
						Topic:         "my-topic",
						CorrelationId: 200,
					},
				},
			},
			e: Layer7{
				Type:      flow.L7FlowType_REQUEST,
				LatencyNs: 15,
				Kafka: Kafka{
					APIVersion:    100,
					CorrelationId: 200,
					Topic:         "my-topic",
					ErrorCode:     1,
				},
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, protoToL7(u.in))
		})
	}
}

func TestKafka_isEmpty(t *testing.T) {
	uu := map[string]struct {
		in Kafka
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: Kafka{
				APIKey:        "blah",
				Topic:         "blee",
				APIVersion:    1,
				CorrelationId: 2,
				ErrorCode:     3,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}

func TestDNS_toProto(t *testing.T) {
	uu := map[string]struct {
		in DNS
		e  *flow.Layer7_Dns
	}{
		"empty": {},

		"full": {
			in: DNS{
				Query:             "example.com",
				TTL:               10,
				Ips:               []string{"1.1.1.1", "1.1.1.2"},
				CNames:            []string{"a", "b"},
				ObservationSource: "src",
				RCode:             1,
				Qtypes:            []string{"A", "AAAA"},
				Rtypes:            []string{"CNAME"},
			},
			e: &flow.Layer7_Dns{
				Dns: &flow.DNS{
					Query:             "example.com",
					Ttl:               10,
					Ips:               []string{"1.1.1.1", "1.1.1.2"},
					Cnames:            []string{"a", "b"},
					ObservationSource: "src",
					Rcode:             1,
					Qtypes:            []string{"A", "AAAA"},
					Rrtypes:           []string{"CNAME"},
				},
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func TestDNSIsEmpty(t *testing.T) {
	uu := map[string]struct {
		in DNS
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: DNS{
				Query:             "example.com",
				TTL:               10,
				Ips:               []string{"1.1.1.1"},
				CNames:            []string{"a"},
				ObservationSource: "src",
				RCode:             1,
				Qtypes:            []string{"A"},
				Rtypes:            []string{"AAAA"},
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}

func TestHTTP_toProto(t *testing.T) {
	uu := map[string]struct {
		in HTTP
		e  *flow.Layer7_Http
	}{
		"empty": {},

		"full": {
			in: HTTP{
				Method:   "GET",
				URL:      "/index.html",
				Protocol: "http",
				Code:     200,
				Headers: []HTTPHeader{
					{Key: "a", Value: "b"},
					{Key: "b", Value: "c"},
				},
			},
			e: &flow.Layer7_Http{
				Http: &flow.HTTP{
					Method:   "GET",
					Url:      "/index.html",
					Protocol: "http",
					Code:     200,
					Headers: []*flow.HTTPHeader{
						{Key: "a", Value: "b"},
						{Key: "b", Value: "c"},
					},
				},
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func TestHTTPIsEmpty(t *testing.T) {
	uu := map[string]struct {
		in HTTP
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: HTTP{
				Method:   "GET",
				URL:      "/index.html",
				Protocol: "http",
				Code:     200,
				Headers: []HTTPHeader{
					{Key: "a", Value: "b"},
				},
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
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

func BenchmarkL7Decode(b *testing.B) {
	requestPath, err := url.Parse("http://myhost/some/path")
	require.NoError(b, err)
	lr := &accesslog.LogRecord{
		Type:                accesslog.TypeResponse,
		Timestamp:           fakeTimestamp,
		NodeAddressInfo:     fakeNodeInfo,
		ObservationPoint:    accesslog.Ingress,
		SourceEndpoint:      fakeDestinationEndpoint,
		DestinationEndpoint: fakeSourceEndpoint,
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
			Headers: http.Header{
				"Host":        {"myhost"},
				"Traceparent": {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
			},
		},
	}
	lr.SourceEndpoint.Port = 80
	lr.DestinationEndpoint.Port = 56789

	dnsGetter := &testutils.NoopDNSGetter
	ipGetter := &testutils.NoopIPGetter
	serviceGetter := &testutils.NoopServiceGetter
	endpointGetter := &testutils.NoopEndpointGetter

	parser, err := New(log, dnsGetter, ipGetter, serviceGetter, endpointGetter)
	require.NoError(b, err)

	f := &flowpb.Flow{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parser.Decode(lr, f)
	}
}

func Test_decodeVerdict(t *testing.T) {
	assert.Equal(t, flowpb.Verdict_FORWARDED, decodeVerdict(accesslog.VerdictForwarded))
	assert.Equal(t, flowpb.Verdict_DROPPED, decodeVerdict(accesslog.VerdictDenied))
	assert.Equal(t, flowpb.Verdict_ERROR, decodeVerdict(accesslog.VerdictError))
	assert.Equal(t, flowpb.Verdict_REDIRECTED, decodeVerdict(accesslog.VerdictRedirected))
	assert.Equal(t, flowpb.Verdict_VERDICT_UNKNOWN, decodeVerdict("bad"))
}

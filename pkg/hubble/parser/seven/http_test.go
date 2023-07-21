// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestDecodeL7HTTPRequest(t *testing.T) {
	requestPath, err := url.Parse("http://myhost/some/path")
	require.NoError(t, err)
	lr := &accesslog.LogRecord{
		Type:                accesslog.TypeRequest,
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
			Code:     0,
			Method:   "POST",
			URL:      requestPath,
			Protocol: "HTTP/1.1",
			Headers: http.Header{
				"Host":        {"myhost"},
				"Traceparent": {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
			},
		},
	}
	lr.SourceEndpoint.Port = 56789
	lr.DestinationEndpoint.Port = 80

	dnsGetter := &testutils.FakeFQDNCache{
		OnGetNamesOf: func(epID uint32, ip netip.Addr) (names []string) {
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
		OnGetK8sMetadata: func(ip netip.Addr) *ipcache.K8sMetadata {
			if ip == netip.MustParseAddr(fakeDestinationEndpoint.IPv4) {
				return &ipcache.K8sMetadata{
					Namespace: "default",
					PodName:   "pod-1234",
				}
			}
			return nil
		},
	}
	serviceGetter := &testutils.FakeServiceGetter{
		OnGetServiceByAddr: func(ip netip.Addr, port uint16) *flowpb.Service {
			if ip == netip.MustParseAddr(fakeDestinationEndpoint.IPv4) && (port == fakeDestinationEndpoint.Port) {
				return &flowpb.Service{
					Name:      "service-1234",
					Namespace: "default",
				}
			}
			return nil
		},
	}
	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint v1.EndpointInfo, ok bool) {
			switch {
			case ip == netip.MustParseAddr(fakeSourceEndpoint.IPv4):
				return &testutils.FakeEndpointInfo{
					ID: fakeSourceEndpoint.ID,
				}, true
			case ip == netip.MustParseAddr(fakeDestinationEndpoint.IPv4):
				return &testutils.FakeEndpointInfo{
					ID: fakeDestinationEndpoint.ID,
				}, true
			}
			return nil, false
		},
	}

	parser, err := New(log, dnsGetter, IPGetter, serviceGetter, endpointGetter)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	err = parser.Decode(lr, f)
	require.NoError(t, err)

	assert.Equal(t, fakeSourceEndpoint.IPv4, f.GetIP().GetSource())
	assert.Equal(t, uint32(56789), f.GetL4().GetTCP().GetSourcePort())
	assert.Equal(t, []string{"endpoint-4321"}, f.GetSourceNames())
	assert.Equal(t, fakeSourceEndpoint.Labels, f.GetSource().GetLabels())
	assert.Equal(t, "", f.GetSource().GetNamespace())
	assert.Equal(t, "", f.GetSource().GetPodName())
	assert.Equal(t, "", f.GetSourceService().GetNamespace())
	assert.Equal(t, "", f.GetSourceService().GetName())

	assert.Equal(t, fakeDestinationEndpoint.IPv4, f.GetIP().GetDestination())
	assert.Equal(t, uint32(80), f.GetL4().GetTCP().GetDestinationPort())
	assert.Equal(t, []string{"endpoint-1234"}, f.GetDestinationNames())
	assert.Equal(t, fakeDestinationEndpoint.Labels, f.GetDestination().GetLabels())
	assert.Equal(t, "default", f.GetDestination().GetNamespace())
	assert.Equal(t, "pod-1234", f.GetDestination().GetPodName())
	assert.Equal(t, "default", f.GetDestinationService().GetNamespace())
	assert.Equal(t, "service-1234", f.GetDestinationService().GetName())

	assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())

	assert.Equal(t, &flowpb.HTTP{
		Code:     0,
		Method:   "POST",
		Url:      "http://myhost/some/path",
		Protocol: "HTTP/1.1",
		Headers: []*flowpb.HTTPHeader{
			{Key: "Host", Value: "myhost"},
			{Key: "Traceparent", Value: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		},
	}, f.GetL7().GetHttp())
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", f.GetTraceContext().GetParent().GetTraceId())
}

func TestDecodeL7HTTPRecordResponse(t *testing.T) {
	requestPath, err := url.Parse("http://myhost/some/path")
	require.NoError(t, err)
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
		},
	}
	lr.SourceEndpoint.Port = 80
	lr.DestinationEndpoint.Port = 56789

	dnsGetter := &testutils.FakeFQDNCache{
		OnGetNamesOf: func(epID uint32, ip netip.Addr) (names []string) {
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
		OnGetK8sMetadata: func(ip netip.Addr) *ipcache.K8sMetadata {
			if ip == netip.MustParseAddr(fakeDestinationEndpoint.IPv4) {
				return &ipcache.K8sMetadata{
					Namespace: "default",
					PodName:   "pod-1234",
				}
			}
			return nil
		},
	}
	serviceGetter := &testutils.FakeServiceGetter{
		OnGetServiceByAddr: func(ip netip.Addr, port uint16) *flowpb.Service {
			if ip == netip.MustParseAddr(fakeDestinationEndpoint.IPv4) && (port == fakeDestinationEndpoint.Port) {
				return &flowpb.Service{
					Name:      "service-1234",
					Namespace: "default",
				}
			}
			return nil
		},
	}
	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint v1.EndpointInfo, ok bool) {
			switch {
			case ip.String() == fakeSourceEndpoint.IPv4:
				return &testutils.FakeEndpointInfo{
					ID: fakeSourceEndpoint.ID,
				}, true
			case ip.String() == fakeDestinationEndpoint.IPv4:
				return &testutils.FakeEndpointInfo{
					ID: fakeDestinationEndpoint.ID,
				}, true
			}
			return nil, false
		},
	}

	parser, err := New(log, dnsGetter, IPGetter, serviceGetter, endpointGetter)
	require.NoError(t, err)

	f := &flowpb.Flow{}
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

	assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())

	assert.Equal(t, &flowpb.HTTP{
		Code:     404,
		Method:   "POST",
		Url:      "http://myhost/some/path",
		Protocol: "HTTP/1.1",
	}, f.GetL7().GetHttp())
}

func TestDecodeL7HTTPResponseTime(t *testing.T) {
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

	parser, err := New(log, nil, nil, nil, nil)
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

	f := &flowpb.Flow{}
	err = parser.Decode(request, f)
	require.NoError(t, err)
	_, ok := parser.timestampCache.Get(requestID)
	assert.True(t, ok, "request id should be in the cache")

	f.Reset()
	err = parser.Decode(response, f)
	require.NoError(t, err)
	assert.Equal(t, 1*time.Second, time.Duration(f.GetL7().GetLatencyNs()))
	_, ok = parser.timestampCache.Get(requestID)
	assert.False(t, ok, "request id should not be in the cache")

	// it should handle the case where the request id is not in the cache for response type.
	f = &flowpb.Flow{}
	err = parser.Decode(response, f)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), f.GetL7().GetLatencyNs())
	_, ok = parser.timestampCache.Get(requestID)
	assert.False(t, ok, "request id should not be in the cache")
}

func TestGetL7HTTPResponseTraceID(t *testing.T) {
	requestID := "req-id"
	requestRecord := &accesslog.LogRecordHTTP{
		Method:   "GET",
		Protocol: "HTTP/1.1",
		URL: &url.URL{
			Scheme: "http",
			Host:   "example.com",
			Path:   "/",
		},
		Headers: http.Header{
			"X-Request-Id": {requestID},
			"Host":         {"myhost"},
			"Traceparent":  {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		},
	}
	responseRecord := &accesslog.LogRecordHTTP{
		Code:     200,
		Method:   "GET",
		Protocol: "HTTP/1.1",
		URL: &url.URL{
			Scheme: "http",
			Host:   "example.com",
			Path:   "/",
		},
		Headers: http.Header{
			"X-Request-Id": {requestID},
		},
	}
	requestTimestamp := time.Unix(0, 0).Format(time.RFC3339Nano)
	responseTimestamp := time.Unix(1, 0).Format(time.RFC3339Nano)

	parser, err := New(log, nil, nil, nil, nil)
	require.NoError(t, err)

	request := &accesslog.LogRecord{
		Type:      accesslog.TypeRequest,
		Timestamp: requestTimestamp,
		HTTP:      requestRecord,
	}

	response := &accesslog.LogRecord{
		Type:      accesslog.TypeResponse,
		Timestamp: responseTimestamp,
		HTTP:      responseRecord,
	}

	f := &flowpb.Flow{}
	err = parser.Decode(request, f)
	require.NoError(t, err)
	_, ok := parser.traceContextCache.Get(requestID)
	assert.True(t, ok, "request id should be in the cache")

	f.Reset()
	err = parser.Decode(response, f)
	require.NoError(t, err)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", f.GetTraceContext().GetParent().GetTraceId())
	_, ok = parser.traceContextCache.Get(requestID)
	assert.False(t, ok, "request id should not be in the cache")

	// it should handle the case where the request id is not in the cache for response type.
	f = &flowpb.Flow{}
	err = parser.Decode(response, f)
	require.NoError(t, err)
	// no requestID means no traceID for response
	assert.Empty(t, f.GetTraceContext().GetParent().GetTraceId())
	_, ok = parser.traceContextCache.Get(requestID)
	assert.False(t, ok, "request id should not be in the cache")
}

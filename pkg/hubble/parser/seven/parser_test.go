// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
)

type nodeLabelsCall struct {
	ip   netip.Addr
	hint getters.NodeClusterHint
}

type recordingNodeLabelsGetter struct {
	calls   []nodeLabelsCall
	results [][]string
	onCall  func(netip.Addr, getters.NodeClusterHint) []string
}

func (g *recordingNodeLabelsGetter) GetNodeLabels(ip netip.Addr, hint getters.NodeClusterHint) []string {
	callIndex := len(g.calls)
	g.calls = append(g.calls, nodeLabelsCall{ip: ip, hint: hint})
	if g.onCall != nil {
		return g.onCall(ip, hint)
	}
	if callIndex < len(g.results) {
		return g.results[callIndex]
	}
	return nil
}

type sevenEndpointInfoRegistryFunc func(*accesslog.EndpointInfo, netip.Addr)

func (f sevenEndpointInfoRegistryFunc) FillEndpointInfo(_ context.Context, info *accesslog.EndpointInfo, addr netip.Addr) {
	f(info, addr)
}

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
		Labels:   labels.ParseLabelArray("k1=v1", "k2=v2"),
	}
	fakeDestinationEndpoint = accesslog.EndpointInfo{
		ID:       4321,
		IPv4:     "10.16.32.20",
		IPv6:     "f00d::a10:0:0:1234",
		Port:     80,
		Identity: 6789,
		Labels:   labels.ParseLabelArray("k3=v3", "k4=v4"),
	}
)

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

	parser, err := New(hivetest.Logger(b), dnsGetter, ipGetter, serviceGetter, endpointGetter)
	require.NoError(b, err)

	f := &flowpb.Flow{}
	b.ReportAllocs()

	for b.Loop() {
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

func Test_decodeEndpoint(t *testing.T) {
	epi := accesslog.EndpointInfo{
		ID:       1234,
		Identity: 9876,
		Labels: labels.ParseLabelArray(
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.kubernetes.pod.namespace=kube-system",
			"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=kube-system",
			"k8s:k8s-app=hubble-ui",
			"k8s:app.kubernetes.io/name=hubble-ui",
			"k8s:app.kubernetes.io/part-of=cilium",
		),
	}
	expected := &flowpb.Endpoint{
		ID:          1234,
		Identity:    9876,
		ClusterName: "default",
		Namespace:   "kube-system",
		Labels: []string{
			"k8s:app.kubernetes.io/name=hubble-ui",
			"k8s:app.kubernetes.io/part-of=cilium",
			"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=kube-system",
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.kubernetes.pod.namespace=kube-system",
			"k8s:k8s-app=hubble-ui",
		},
		PodName: "hubble-ui",
	}
	ep := decodeEndpoint(epi, "kube-system", "hubble-ui")
	assert.Equal(t, expected, ep)
}

func TestL7NodeLabelsUsesFinalIPOrientationAndIdentityProvenance(t *testing.T) {
	tests := []struct {
		name               string
		sourceIP           netip.Addr
		destinationIP      netip.Addr
		addressing         accesslog.AddressingInfo
		wantIPVersion      flowpb.IPVersion
		wantSourceIdentity identity.NumericIdentity
		wantDestIdentity   identity.NumericIdentity
	}{
		{
			name:          "IPv4 security identity pointers",
			sourceIP:      netip.MustParseAddr("192.0.2.10"),
			destinationIP: netip.MustParseAddr("192.0.2.20"),
			addressing: accesslog.AddressingInfo{
				SrcSecIdentity: &identity.Identity{ID: 101},
				SrcIdentity:    901,
				DstSecIdentity: &identity.Identity{ID: 202},
				DstIdentity:    902,
			},
			wantIPVersion:      flowpb.IPVersion_IPv4,
			wantSourceIdentity: 101,
			wantDestIdentity:   202,
		},
		{
			name:          "IPv6 numeric identity fallbacks",
			sourceIP:      netip.MustParseAddr("2001:db8::10"),
			destinationIP: netip.MustParseAddr("2001:db8::20"),
			addressing: accesslog.AddressingInfo{
				SrcIdentity: 303,
				DstIdentity: 404,
			},
			wantIPVersion:      flowpb.IPVersion_IPv6,
			wantSourceIdentity: 303,
			wantDestIdentity:   404,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &accesslog.LogRecord{
				Type:      accesslog.TypeSample,
				Timestamp: fakeTimestamp,
			}
			addressing := tt.addressing
			addressing.SrcIPPort = netip.AddrPortFrom(tt.sourceIP, 1234).String()
			addressing.DstIPPort = netip.AddrPortFrom(tt.destinationIP, 4321).String()
			registry := sevenEndpointInfoRegistryFunc(func(info *accesslog.EndpointInfo, addr netip.Addr) {
				if addr.Is4() {
					info.IPv4 = addr.String()
				} else {
					info.IPv6 = addr.String()
				}
			})
			accesslog.LogTags.Addressing(t.Context(), addressing)(record, registry)

			sourceLabels := []string{"node=source"}
			destinationLabels := []string{"node=destination"}
			getter := &recordingNodeLabelsGetter{results: [][]string{sourceLabels, destinationLabels}}
			parser, err := New(
				hivetest.Logger(t),
				&testutils.NoopDNSGetter,
				&testutils.NoopIPGetter,
				&testutils.NoopServiceGetter,
				&testutils.NoopEndpointGetter,
				options.WithNodeLabelsGetter(getter),
			)
			require.NoError(t, err)

			decoded := &flowpb.Flow{}
			require.NoError(t, parser.Decode(record, decoded))

			require.Equal(t, tt.wantIPVersion, decoded.GetIP().GetIpVersion())
			require.Equal(t, []nodeLabelsCall{
				{
					ip: tt.sourceIP,
					hint: getters.NodeClusterHint{
						Identity:      tt.wantSourceIdentity,
						IdentityKnown: true,
					},
				},
				{
					ip: tt.destinationIP,
					hint: getters.NodeClusterHint{
						Identity:      tt.wantDestIdentity,
						IdentityKnown: true,
					},
				},
			}, getter.calls)
			require.Equal(t, sourceLabels, decoded.GetSourceNodeLabels())
			require.Equal(t, destinationLabels, decoded.GetDestinationNodeLabels())
			require.Same(t, &sourceLabels[0], &decoded.SourceNodeLabels[0], "source labels must be assigned without copying")
			require.Same(t, &destinationLabels[0], &decoded.DestinationNodeLabels[0], "destination labels must be assigned without copying")
		})
	}
}

func TestL7IdentityProvenanceRejectsUserspaceFilledIdentity(t *testing.T) {
	sourceIP := netip.MustParseAddr("192.0.2.30")
	destinationIP := netip.MustParseAddr("192.0.2.40")
	record := &accesslog.LogRecord{
		Type:      accesslog.TypeSample,
		Timestamp: fakeTimestamp,
	}
	addressing := accesslog.AddressingInfo{
		SrcIPPort:      netip.AddrPortFrom(sourceIP, 1234).String(),
		DstIPPort:      netip.AddrPortFrom(destinationIP, 4321).String(),
		SrcSecIdentity: &identity.Identity{ID: identity.IdentityUnknown},
		SrcIdentity:    505,
		DstSecIdentity: &identity.Identity{ID: identity.IdentityUnknown},
		DstIdentity:    606,
	}
	registry := sevenEndpointInfoRegistryFunc(func(info *accesslog.EndpointInfo, addr netip.Addr) {
		info.IPv4 = addr.String()
		info.Labels = labels.ParseLabelArray("k8s:io.cilium.k8s.policy.cluster=userspace-only")
		switch addr {
		case sourceIP:
			require.Zero(t, info.Identity, "the unknown pointer must override the numeric source fallback")
			info.Identity = 7001
		case destinationIP:
			require.Zero(t, info.Identity, "the unknown pointer must override the numeric destination fallback")
			info.Identity = 7002
		default:
			t.Fatalf("unexpected endpoint address %s", addr)
		}
	})
	accesslog.LogTags.Addressing(t.Context(), addressing)(record, registry)
	require.Equal(t, uint64(7001), record.SourceEndpoint.Identity)
	require.Equal(t, uint64(7002), record.DestinationEndpoint.Identity)
	require.False(t, record.SourceEndpoint.SecurityIdentityProvided)
	require.False(t, record.DestinationEndpoint.SecurityIdentityProvided)

	getter := &recordingNodeLabelsGetter{
		onCall: func(_ netip.Addr, hint getters.NodeClusterHint) []string {
			if !hint.IdentityKnown {
				return nil
			}
			return []string{"must-not-resolve=true"}
		},
	}
	parser, err := New(
		hivetest.Logger(t),
		&testutils.NoopDNSGetter,
		&testutils.NoopIPGetter,
		&testutils.NoopServiceGetter,
		&testutils.NoopEndpointGetter,
		options.WithNodeLabelsGetter(getter),
	)
	require.NoError(t, err)

	decoded := &flowpb.Flow{}
	require.NoError(t, parser.Decode(record, decoded))

	require.Equal(t, []nodeLabelsCall{
		{ip: sourceIP, hint: getters.NodeClusterHint{Identity: 7001, IdentityKnown: false}},
		{ip: destinationIP, hint: getters.NodeClusterHint{Identity: 7002, IdentityKnown: false}},
	}, getter.calls)
	require.Equal(t, "userspace-only", decoded.GetSource().GetClusterName(), "the fixture must expose tempting userspace cluster metadata")
	require.Equal(t, "userspace-only", decoded.GetDestination().GetClusterName(), "the fixture must expose tempting userspace cluster metadata")
	require.Empty(t, decoded.GetSourceNodeLabels())
	require.Empty(t, decoded.GetDestinationNodeLabels())
}

func TestL7NodeLabelsNilGetterPreservesOutputAndClearsReuse(t *testing.T) {
	sourceIP := netip.MustParseAddr("192.0.2.50")
	destinationIP := netip.MustParseAddr("192.0.2.60")
	record := &accesslog.LogRecord{
		Type:      accesslog.TypeSample,
		Timestamp: fakeTimestamp,
	}
	registry := sevenEndpointInfoRegistryFunc(func(info *accesslog.EndpointInfo, addr netip.Addr) {
		info.IPv4 = addr.String()
	})
	accesslog.LogTags.Addressing(t.Context(), accesslog.AddressingInfo{
		SrcIPPort:   netip.AddrPortFrom(sourceIP, 1234).String(),
		DstIPPort:   netip.AddrPortFrom(destinationIP, 4321).String(),
		SrcIdentity: 101,
		DstIdentity: 202,
	})(record, registry)

	baselineParser, err := New(
		hivetest.Logger(t),
		&testutils.NoopDNSGetter,
		&testutils.NoopIPGetter,
		&testutils.NoopServiceGetter,
		&testutils.NoopEndpointGetter,
	)
	require.NoError(t, err)
	baseline := &flowpb.Flow{}
	require.NoError(t, baselineParser.Decode(record, baseline))

	recorder := &recordingNodeLabelsGetter{results: [][]string{{"must-not-be-called"}}}
	nilParser, err := New(
		hivetest.Logger(t),
		&testutils.NoopDNSGetter,
		&testutils.NoopIPGetter,
		&testutils.NoopServiceGetter,
		&testutils.NoopEndpointGetter,
		options.WithNodeLabelsGetter(recorder),
		options.WithNodeLabelsGetter(nil),
	)
	require.NoError(t, err)
	reused := &flowpb.Flow{
		SourceNodeLabels:      []string{"stale-source-label"},
		DestinationNodeLabels: []string{"stale-destination-label"},
	}
	require.NoError(t, nilParser.Decode(record, reused))

	require.Empty(t, recorder.calls, "a final nil option must disable the getter")
	require.Empty(t, reused.GetSourceNodeLabels())
	require.Empty(t, reused.GetDestinationNodeLabels())
	require.Equal(t, baseline, reused, "nil getter output must match the existing parser behavior")
}

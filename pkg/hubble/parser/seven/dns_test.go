// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestDecodeL7DNSRecord(t *testing.T) {
	lr := &accesslog.LogRecord{
		Type:                accesslog.TypeResponse,
		Timestamp:           fakeTimestamp,
		NodeAddressInfo:     fakeNodeInfo,
		ObservationPoint:    accesslog.Ingress,
		SourceEndpoint:      fakeDestinationEndpoint,
		DestinationEndpoint: fakeSourceEndpoint,
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
	lr.SourceEndpoint.Port = 53
	lr.DestinationEndpoint.Port = 56789

	dnsGetter := &testutils.NoopDNSGetter
	ipGetter := &testutils.NoopIPGetter
	serviceGetter := &testutils.NoopServiceGetter
	endpointGetter := &testutils.NoopEndpointGetter

	parser, err := New(log, dnsGetter, ipGetter, serviceGetter, endpointGetter)
	require.NoError(t, err)

	f := &flowpb.Flow{}
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

	assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())

	assert.Equal(t, &flowpb.DNS{
		Query:             "deathstar.empire.svc.cluster.local.",
		Ips:               []string{"1.2.3.4"},
		Ttl:               5,
		ObservationSource: string(accesslog.DNSSourceProxy),
		Rcode:             0,
		Qtypes:            []string{"A"},
		Rrtypes:           []string{"A"},
	}, f.GetL7().GetDns())
}

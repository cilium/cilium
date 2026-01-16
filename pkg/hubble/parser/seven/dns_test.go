// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/ir"
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
			IPs:               []netip.Addr{netip.MustParseAddr("1.2.3.4")},
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

	parser, err := New(hivetest.Logger(t), dnsGetter, ipGetter, serviceGetter, endpointGetter)
	require.NoError(t, err)

	var f ir.Flow
	err = parser.Decode(lr, &f)
	require.NoError(t, err)

	ts := f.CreatedOn
	assert.Equal(t, fakeTimestamp, ts.Format(time.RFC3339Nano))

	assert.Equal(t, fakeSourceEndpoint.IPv6, f.IP.Destination.To16().String())
	assert.Equal(t, uint32(56789), f.L4.UDP.DestinationPort)
	assert.Equal(t, []string(nil), f.DestinationNames)
	assert.Equal(t, fakeSourceEndpoint.Labels.GetModel(), f.Destination.Labels)
	assert.Empty(t, f.Destination.Namespace)
	assert.Empty(t, f.Destination.PodName)
	assert.Empty(t, f.DestinationService.Namespace)
	assert.Empty(t, f.DestinationService.Name)

	assert.Equal(t, fakeDestinationEndpoint.IPv6, f.IP.Source.To16().String())
	assert.Equal(t, uint32(53), f.L4.UDP.SourcePort)
	assert.Equal(t, []string(nil), f.SourceNames)
	assert.Equal(t, fakeDestinationEndpoint.Labels.GetModel(), f.Source.Labels)
	assert.Empty(t, f.Source.Namespace)
	assert.Empty(t, f.Source.PodName)
	assert.Empty(t, f.SourceService.Namespace)
	assert.Empty(t, f.SourceService.Name)

	assert.Equal(t, flowpb.Verdict_FORWARDED, f.Verdict)

	assert.Equal(t, ir.DNS{
		Query:             "deathstar.empire.svc.cluster.local.",
		Ips:               []string{"1.2.3.4"},
		TTL:               5,
		ObservationSource: string(accesslog.DNSSourceProxy),
		RCode:             0,
		Qtypes:            []string{"A"},
		Rtypes:            []string{"A"},
	}, f.L7.DNS)
}

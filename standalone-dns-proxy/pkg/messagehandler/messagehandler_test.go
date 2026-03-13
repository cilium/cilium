// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/dns"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/time"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

type mockConnHandler struct {
	last *pb.FQDNMapping
}

func (m *mockConnHandler) NotifyOnMsg(msg *pb.FQDNMapping) error {
	m.last = msg
	return nil
}

func (m *mockConnHandler) StartConnection() {}

func (m *mockConnHandler) StopConnection() {}

func (m *mockConnHandler) IsConnected() bool {
	return true
}

func newTestHandler(t *testing.T) (*messageHandler, *mockConnHandler, *endpoint.Endpoint) {
	t.Helper()

	// Minimal endpoint instance with a security identity.
	ep := &endpoint.Endpoint{
		SecurityIdentity: &identity.Identity{
			ID: identity.NumericIdentity(111),
		},
	}
	mc := &mockConnHandler{}
	h := &messageHandler{
		Logger:      hivetest.Logger(t),
		ConnHandler: mc,
	}
	return h, mc, ep
}

func buildResponseDetails() dnsproxy.MsgDetails {
	return dnsproxy.MsgDetails{
		QName:       "example.com.",
		ResponseIPs: []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("2001:db8::1")},
		TTL:         100,
		RCode:       dns.RcodeSuccess,
		AnswerTypes: []uint16{dns.TypeA, dns.TypeAAAA},
		QTypes:      []uint16{dns.TypeA},
		Response:    true,
		CNAMEs:      []string{"alias.example.com."},
	}
}

func buildRequestDetails() dnsproxy.MsgDetails {
	return dnsproxy.MsgDetails{
		QName:    "request.example.com.",
		TTL:      0,
		RCode:    dns.RcodeSuccess,
		QTypes:   []uint16{dns.TypeA},
		Response: false,
	}
}

// buildStatWithTimings returns a ProxyRequestContext with known durations set on each SpanStat.
func buildStatWithTimings() *dnsproxy.ProxyRequestContext {
	stat := &dnsproxy.ProxyRequestContext{}
	stat.TotalTime.SetSuccessDuration(10 * time.Millisecond)
	stat.ProcessingTime.SetSuccessDuration(1 * time.Millisecond)
	stat.UpstreamTime.SetSuccessDuration(5 * time.Millisecond)
	stat.SemaphoreAcquireTime.SetSuccessDuration(500 * time.Microsecond)
	stat.PolicyCheckTime.SetSuccessDuration(200 * time.Microsecond)
	stat.PolicyGenerationTime.SetSuccessDuration(100 * time.Microsecond)
	stat.DataplaneTime.SetSuccessDuration(2 * time.Millisecond)
	stat.QnameLockTime.SetSuccessDuration(50 * time.Microsecond)
	stat.UpdateEpCacheTime.SetSuccessDuration(300 * time.Microsecond)
	stat.UpdateNmCacheTime.SetSuccessDuration(150 * time.Microsecond)
	return stat
}

func TestNotifyOnDNSMsg(t *testing.T) {
	type testCase struct {
		name           string
		details        dnsproxy.MsgDetails
		epIPPort       string
		server         string
		serverID       identity.NumericIdentity
		protocol       string
		allowed        bool
		stat           *dnsproxy.ProxyRequestContext
		nilEp          bool
		expectErr      bool
		validate       func(t *testing.T, msg *pb.FQDNMapping)
	}

	tests := []testCase{
		{
			name:     "response with all fields",
			details:  buildResponseDetails(),
			epIPPort: "10.1.1.10:5353",
			server:   "8.8.8.8:53",
			serverID: identity.NumericIdentity(42),
			protocol: "tcp",
			allowed:  false,
			stat:     buildStatWithTimings(),
			validate: func(t *testing.T, msg *pb.FQDNMapping) {
				// FQDNMapping top-level fields
				require.Equal(t, "example.com.", msg.Fqdn)
				require.ElementsMatch(t, [][]byte{[]byte("1.2.3.4"), []byte("2001:db8::1")}, msg.RecordIp)
				require.Equal(t, uint32(100), msg.Ttl)
				require.Equal(t, "10.1.1.10", string(msg.SourceIp))
				require.Equal(t, uint32(111), msg.SourceIdentity)
				require.Equal(t, uint32(dns.RcodeSuccess), msg.ResponseCode)

				// MetricsData fields
				md := msg.MetricsData
				require.NotNil(t, md)
				require.Equal(t, uint32(5353), md.SourcePort)
				require.Equal(t, "8.8.8.8:53", md.ServerAddr)
				require.Equal(t, uint32(42), md.ServerIdentity)
				require.Equal(t, "tcp", md.Protocol)
				require.False(t, md.Allowed)
				require.Empty(t, md.ErrorMessage)
				require.False(t, md.IsTimeout)

				// DnsResponseData fields
				drd := md.DnsResponseData
				require.NotNil(t, drd)
				require.True(t, drd.IsResponse)
				require.Equal(t, []string{"alias.example.com."}, drd.Cnames)
				require.Equal(t, []uint32{uint32(dns.TypeA)}, drd.Qtypes)
				require.ElementsMatch(t, []uint32{uint32(dns.TypeA), uint32(dns.TypeAAAA)}, drd.AnswerTypes)

				// ProcessingStats timing fields
				ps := md.ProcessingStats
				require.NotNil(t, ps)
				require.Equal(t, int64(10*time.Millisecond), ps.TotalTimeNs)
				require.Equal(t, int64(1*time.Millisecond), ps.ProcessingTimeNs)
				require.Equal(t, int64(5*time.Millisecond), ps.UpstreamTimeNs)
				require.Equal(t, int64(500*time.Microsecond), ps.SemaphoreAcquireTimeNs)
				require.Equal(t, int64(200*time.Microsecond), ps.PolicyCheckTimeNs)
				require.Equal(t, int64(100*time.Microsecond), ps.PolicyGenerationTimeNs)
				require.Equal(t, int64(2*time.Millisecond), ps.DataplaneTimeNs)
				require.Equal(t, int64(50*time.Microsecond), ps.QnameLockTimeNs)
				require.Equal(t, int64(300*time.Microsecond), ps.UpdateEpCacheTimeNs)
				require.Equal(t, int64(150*time.Microsecond), ps.UpdateNmCacheTimeNs)
			},
		},
		{
			name:     "invalid source ip:port still sends message",
			details:  buildResponseDetails(),
			epIPPort: "bad-format",
			server:   "8.8.4.4:53",
			protocol: "udp",
			allowed:  true,
			stat:     &dnsproxy.ProxyRequestContext{},
			validate: func(t *testing.T, msg *pb.FQDNMapping) {
				// Source fields are empty because SplitHostPort failed
				require.Empty(t, msg.SourceIp)
				require.Equal(t, uint32(0), msg.MetricsData.SourcePort)
				// But the DNS details are still present
				require.Equal(t, "example.com.", msg.Fqdn)
				require.Equal(t, uint32(100), msg.Ttl)
			},
		},
		{
			name:     "dns request (non-response)",
			details:  buildRequestDetails(),
			epIPPort: "10.1.1.10:12345",
			server:   "8.8.8.8:53",
			protocol: "udp",
			allowed:  true,
			stat:     &dnsproxy.ProxyRequestContext{},
			validate: func(t *testing.T, msg *pb.FQDNMapping) {
				require.Equal(t, "request.example.com.", msg.Fqdn)
				require.Nil(t, msg.RecordIp)
				require.Equal(t, uint32(0), msg.Ttl)
				require.Equal(t, uint32(12345), msg.MetricsData.SourcePort)

				drd := msg.MetricsData.DnsResponseData
				require.NotNil(t, drd)
				require.False(t, drd.IsResponse)
				require.Nil(t, drd.Cnames)
				require.Nil(t, drd.AnswerTypes)
				require.Equal(t, []uint32{uint32(dns.TypeA)}, drd.Qtypes)
			},
		},
		{
			name:     "with proxy error",
			details:  buildResponseDetails(),
			epIPPort: "10.1.1.10:5353",
			server:   "8.8.8.8:53",
			protocol: "udp",
			allowed:  false,
			stat: &dnsproxy.ProxyRequestContext{
				Err: errors.New("upstream failure"),
			},
			validate: func(t *testing.T, msg *pb.FQDNMapping) {
				require.Equal(t, "upstream failure", msg.MetricsData.ErrorMessage)
				require.False(t, msg.MetricsData.IsTimeout)
			},
		},
		{
			name:     "nil endpoint still sends metrics",
			details:  buildResponseDetails(),
			epIPPort: "10.1.1.10:5353",
			server:   "8.8.8.8:53",
			protocol: "udp",
			allowed:  false,
			nilEp:    true,
			stat: &dnsproxy.ProxyRequestContext{
				Err: fmt.Errorf("cannot extract endpoint IP from DNS request: %w", errors.New("parse error")),
			},
			validate: func(t *testing.T, msg *pb.FQDNMapping) {
				// Source identity is zero because ep was nil
				require.Equal(t, uint32(0), msg.SourceIdentity)
				// But metrics data and error are still forwarded
				require.NotEmpty(t, msg.MetricsData.ErrorMessage)
				require.Equal(t, "example.com.", msg.Fqdn)
				require.Equal(t, uint32(5353), msg.MetricsData.SourcePort)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, mc, ep := newTestHandler(t)
			var testEp *endpoint.Endpoint
			if !tc.nilEp {
				testEp = ep
			}
			serverAP := netip.MustParseAddrPort(tc.server)
			err := h.NotifyOnDNSMsg(time.Now(), testEp, tc.epIPPort, tc.serverID, serverAP, tc.details, tc.protocol, tc.allowed, tc.stat)
			if tc.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, mc.last)
			if tc.validate != nil {
				tc.validate(t, mc.last)
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
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

func newTestHandler(t *testing.T, nilEp bool) (*messageHandler, *mockConnHandler, *endpoint.Endpoint) {
	t.Helper()

	var ep *endpoint.Endpoint
	if !nilEp {
		ep = &endpoint.Endpoint{
			SecurityIdentity: &identity.Identity{
				ID: identity.NumericIdentity(111),
			},
		}
	}
	mc := &mockConnHandler{}
	h := &messageHandler{
		Logger:      hivetest.Logger(t),
		ConnHandler: mc,
	}
	return h, mc, ep
}

func buildResponseDetails() *dnsproxy.MsgDetails {
	return &dnsproxy.MsgDetails{
		QName:       "example.com.",
		ResponseIPs: []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("2001:db8::1")},
		TTL:         100,
		RCode:       dns.RcodeSuccess,
		AnswerTypes: []uint16{dns.TypeA, dns.TypeAAAA},
		QTypes:      []uint16{dns.TypeA},
		Response:    true,
	}
}

func TestNotifyOnDNSMsg(t *testing.T) {
	type testCase struct {
		name      string
		details   *dnsproxy.MsgDetails
		epIPPort  string
		server    string
		nilEp     bool
		expectErr bool
		expectMsg *pb.FQDNMapping
	}

	tests := []testCase{
		{
			name:      "success",
			details:   buildResponseDetails(),
			epIPPort:  "10.1.1.10:5353",
			server:    "8.8.8.8:53",
			expectErr: false,
			expectMsg: &pb.FQDNMapping{
				Fqdn:           "example.com.",
				RecordIp:       [][]byte{[]byte("1.2.3.4"), []byte("2001:db8::1")},
				Ttl:            100,
				SourceIp:       []byte("10.1.1.10"),
				SourceIdentity: 111,
				ResponseCode:   0,
			},
		},
		{
			name:      "invalid source ip:port",
			details:   buildResponseDetails(),
			epIPPort:  "bad-format",
			server:    "8.8.4.4:53",
			expectErr: true,
		},
		{
			name:      "nil endpoint",
			details:   buildResponseDetails(),
			epIPPort:  "10.1.1.10:5353",
			server:    "8.8.8.8:53",
			nilEp:     true,
			expectErr: true,
		},
		{
			name:      "empty msg details",
			details:   &dnsproxy.MsgDetails{},
			epIPPort:  "10.1.1.10:5353",
			server:    "1.1.1.1:53",
			expectErr: false,
			expectMsg: &pb.FQDNMapping{
				SourceIp:       []byte("10.1.1.10"),
				SourceIdentity: 111,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, mc, ep := newTestHandler(t, tc.nilEp)
			serverAP := netip.MustParseAddrPort(tc.server)
			err := h.NotifyOnDNSMsg(time.Now(), ep, tc.epIPPort, 0, serverAP, tc.details, "udp", true, &dnsproxy.ProxyRequestContext{})
			if tc.expectErr {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "expected no error")
				require.NotNil(t, mc.last, "expected mapping")
				require.Equal(t, tc.expectMsg.Fqdn, mc.last.Fqdn)
				require.Equal(t, tc.expectMsg.Ttl, mc.last.Ttl)
				require.Equal(t, string(tc.expectMsg.SourceIp), string(mc.last.SourceIp))
				require.Equal(t, tc.expectMsg.SourceIdentity, mc.last.SourceIdentity)
				require.Equal(t, tc.expectMsg.ResponseCode, mc.last.ResponseCode)
				require.ElementsMatch(t, tc.expectMsg.RecordIp, mc.last.RecordIp)
			}
		})
	}
}

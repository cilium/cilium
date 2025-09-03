// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
	"net"
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

func buildResponseMsg() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Response = true
	m.Answer = append(m.Answer,
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.IPv4(1, 2, 3, 4),
		},
		&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    100,
			},
			AAAA: net.ParseIP("2001:db8::1"),
		},
	)
	return m
}

func TestNotifyOnDNSMsg(t *testing.T) {
	type testCase struct {
		name      string
		msg       *dns.Msg
		epIPPort  string
		server    string
		expectErr bool
	}

	tests := []testCase{
		{
			name:      "success",
			msg:       buildResponseMsg(),
			epIPPort:  "10.1.1.10:5353",
			server:    "8.8.8.8:53",
			expectErr: false,
		},
		{
			name:      "invalid message no question",
			msg:       &dns.Msg{},
			epIPPort:  "10.1.1.10:5353",
			server:    "1.1.1.1:53",
			expectErr: true,
		},
		{
			name:      "invalid source ip:port",
			msg:       buildResponseMsg(),
			epIPPort:  "bad-format",
			server:    "8.8.4.4:53",
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, mc, ep := newTestHandler(t)
			serverAP := netip.MustParseAddrPort(tc.server)
			err := h.NotifyOnDNSMsg(time.Now(), ep, tc.epIPPort, 0, serverAP, tc.msg, "udp", true, &dnsproxy.ProxyRequestContext{})
			if tc.expectErr {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "expected no error")
				require.NotNil(t, mc.last, "expected mapping")
				require.Equal(t, "example.com.", mc.last.Fqdn)
				require.Equal(t, uint32(100), mc.last.Ttl)
				require.Equal(t, "10.1.1.10", string(mc.last.SourceIp))
				require.Equal(t, uint32(111), mc.last.SourceIdentity)
				require.Equal(t, uint32(0), mc.last.ResponseCode)
				require.ElementsMatch(t, [][]byte{[]byte("1.2.3.4"), []byte("2001:db8::1")}, mc.last.RecordIp)
			}
		})
	}
}

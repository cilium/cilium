// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func Test_listenerPairConflict(t *testing.T) {
	listener := func(name string, protocol gatewayv1.ProtocolType, port gatewayv1.PortNumber, hostname string) *gatewayv1.Listener {
		l := &gatewayv1.Listener{Name: gatewayv1.SectionName(name), Protocol: protocol, Port: port}
		if hostname != "" {
			l.Hostname = ptr.To(gatewayv1.Hostname(hostname))
		}
		if protocol == gatewayv1.HTTPSProtocolType {
			l.TLS = &gatewayv1.ListenerTLSConfig{Mode: ptr.To(gatewayv1.TLSModeTerminate)}
		}
		return l
	}
	tlsPassthrough := func(name string, port gatewayv1.PortNumber, hostname string) *gatewayv1.Listener {
		l := listener(name, gatewayv1.TLSProtocolType, port, hostname)
		l.TLS = &gatewayv1.ListenerTLSConfig{Mode: ptr.To(gatewayv1.TLSModePassthrough)}
		return l
	}

	tests := []struct {
		name          string
		first, second *gatewayv1.Listener
		want          gatewayv1.ListenerConditionReason
		conflict      bool
	}{
		{
			name:     "different ports",
			first:    listener("a", gatewayv1.HTTPProtocolType, 80, "foo.example.com"),
			second:   listener("b", gatewayv1.HTTPProtocolType, 81, "foo.example.com"),
			want:     "",
			conflict: false,
		},

		{
			name:     "https tls disjoint",
			first:    listener("a", gatewayv1.HTTPSProtocolType, 443, "foo.example.com"),
			second:   tlsPassthrough("b", 443, "bar.example.com"),
			want:     "",
			conflict: false,
		},

		{
			name:     "tcp udp",
			first:    listener("a", gatewayv1.TCPProtocolType, 80, ""),
			second:   listener("b", gatewayv1.UDPProtocolType, 80, ""),
			want:     "",
			conflict: false,
		},

		{
			name:     "duplicate hostname",
			first:    listener("a", gatewayv1.HTTPProtocolType, 80, "foo.example.com"),
			second:   listener("b", gatewayv1.HTTPProtocolType, 80, "foo.example.com"),
			want:     gatewayv1.ListenerReasonHostnameConflict,
			conflict: true,
		},

		{
			name:     "duplicate catch-all",
			first:    listener("a", gatewayv1.HTTPProtocolType, 80, ""),
			second:   listener("b", gatewayv1.HTTPProtocolType, 80, ""),
			want:     gatewayv1.ListenerReasonHostnameConflict,
			conflict: true,
		},

		{
			name:     "https tls overlap",
			first:    listener("a", gatewayv1.HTTPSProtocolType, 443, "*.example.com"),
			second:   tlsPassthrough("b", 443, "foo.example.com"),
			want:     gatewayv1.ListenerReasonProtocolConflict,
			conflict: true,
		},

		{
			name:     "tcp muxed",
			first:    listener("a", gatewayv1.TCPProtocolType, 80, ""),
			second:   listener("b", gatewayv1.HTTPProtocolType, 80, "foo.example.com"),
			want:     gatewayv1.ListenerReasonProtocolConflict,
			conflict: true,
		},

		{
			name:     "duplicate tcp",
			first:    listener("a", gatewayv1.TCPProtocolType, 80, ""),
			second:   listener("b", gatewayv1.TCPProtocolType, 80, ""),
			want:     gatewayv1.ListenerReasonProtocolConflict,
			conflict: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, conflict := listenerPairConflict(tt.first, tt.second)
			assert.Equal(t, tt.conflict, conflict)
			assert.Equal(t, tt.want, reason)
		})
	}
}

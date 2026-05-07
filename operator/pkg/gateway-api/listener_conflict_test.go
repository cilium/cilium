// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func muxedListener(
	name string,
	protocol gatewayv1.ProtocolType,
	port gatewayv1.PortNumber,
	hostname string,
) *gatewayv1.Listener {
	l := &gatewayv1.Listener{
		Name:     gatewayv1.SectionName(name),
		Protocol: protocol,
		Port:     port,
	}
	if hostname != "" {
		l.Hostname = ptr.To(gatewayv1.Hostname(hostname))
	}
	if protocol == gatewayv1.HTTPSProtocolType {
		l.TLS = &gatewayv1.ListenerTLSConfig{Mode: ptr.To(gatewayv1.TLSModeTerminate)}
	}
	return l
}

func tlsPassthroughListener(
	name string,
	port gatewayv1.PortNumber,
	hostname string,
) *gatewayv1.Listener {
	l := muxedListener(name, gatewayv1.TLSProtocolType, port, hostname)
	l.TLS = &gatewayv1.ListenerTLSConfig{Mode: ptr.To(gatewayv1.TLSModePassthrough)}
	return l
}

func l4Listener(
	name string,
	protocol gatewayv1.ProtocolType,
	port gatewayv1.PortNumber,
) *gatewayv1.Listener {
	return &gatewayv1.Listener{
		Name:     gatewayv1.SectionName(name),
		Protocol: protocol,
		Port:     port,
	}
}

func Test_listenerPairConflict(t *testing.T) {
	tests := []struct {
		name       string
		first      *gatewayv1.Listener
		second     *gatewayv1.Listener
		wantReason gatewayv1.ListenerConditionReason
		wantOK     bool
	}{
		{
			name:   "different ports never conflict",
			first:  muxedListener("a", gatewayv1.HTTPProtocolType, 80, "foo.example.com"),
			second: muxedListener("b", gatewayv1.HTTPProtocolType, 81, "foo.example.com"),
		},
		{
			name:   "same protocol distinct hostnames coexist",
			first:  muxedListener("a", gatewayv1.HTTPProtocolType, 80, "foo.example.com"),
			second: muxedListener("b", gatewayv1.HTTPProtocolType, 80, "bar.example.com"),
		},
		{
			name:   "same protocol wildcard and specific hostname coexist",
			first:  muxedListener("a", gatewayv1.HTTPProtocolType, 80, "*.example.com"),
			second: muxedListener("b", gatewayv1.HTTPProtocolType, 80, "foo.example.com"),
		},
		{
			name:       "same protocol identical hostname conflicts",
			first:      muxedListener("a", gatewayv1.HTTPProtocolType, 80, "foo.example.com"),
			second:     muxedListener("b", gatewayv1.HTTPProtocolType, 80, "foo.example.com"),
			wantReason: gatewayv1.ListenerReasonHostnameConflict,
			wantOK:     true,
		},
		{
			name:       "same protocol identical wildcard hostname conflicts",
			first:      muxedListener("a", gatewayv1.HTTPProtocolType, 80, "*.example.com"),
			second:     muxedListener("b", gatewayv1.HTTPProtocolType, 80, "*.example.com"),
			wantReason: gatewayv1.ListenerReasonHostnameConflict,
			wantOK:     true,
		},
		{
			name:       "same protocol both catch-all hostnames conflict",
			first:      muxedListener("a", gatewayv1.HTTPProtocolType, 80, ""),
			second:     muxedListener("b", gatewayv1.HTTPProtocolType, 80, ""),
			wantReason: gatewayv1.ListenerReasonHostnameConflict,
			wantOK:     true,
		},
		{
			name:   "http and https same hostname coexist",
			first:  muxedListener("a", gatewayv1.HTTPProtocolType, 443, "foo.example.com"),
			second: muxedListener("b", gatewayv1.HTTPSProtocolType, 443, "foo.example.com"),
		},
		{
			name:       "https and tls passthrough identical hostname conflict",
			first:      muxedListener("a", gatewayv1.HTTPSProtocolType, 443, "foo.example.com"),
			second:     tlsPassthroughListener("b", 443, "foo.example.com"),
			wantReason: gatewayv1.ListenerReasonProtocolConflict,
			wantOK:     true,
		},
		{
			name:       "https and tls passthrough wildcard overlap conflict",
			first:      muxedListener("a", gatewayv1.HTTPSProtocolType, 443, "*.example.com"),
			second:     tlsPassthroughListener("b", 443, "foo.example.com"),
			wantReason: gatewayv1.ListenerReasonProtocolConflict,
			wantOK:     true,
		},
		{
			name:   "https and tls passthrough disjoint hostnames coexist",
			first:  muxedListener("a", gatewayv1.HTTPSProtocolType, 443, "foo.example.com"),
			second: tlsPassthroughListener("b", 443, "bar.example.com"),
		},
		{
			name:       "tcp and muxed same port conflict",
			first:      l4Listener("a", gatewayv1.TCPProtocolType, 80),
			second:     muxedListener("b", gatewayv1.HTTPProtocolType, 80, "foo.example.com"),
			wantReason: gatewayv1.ListenerReasonProtocolConflict,
			wantOK:     true,
		},
		{
			name:       "duplicate tcp same port conflict",
			first:      l4Listener("a", gatewayv1.TCPProtocolType, 80),
			second:     l4Listener("b", gatewayv1.TCPProtocolType, 80),
			wantReason: gatewayv1.ListenerReasonProtocolConflict,
			wantOK:     true,
		},
		{
			name:   "tcp and udp same port coexist",
			first:  l4Listener("a", gatewayv1.TCPProtocolType, 80),
			second: l4Listener("b", gatewayv1.UDPProtocolType, 80),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, ok := listenerPairConflict(tt.first, tt.second)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantReason, reason)

			reasonSwapped, okSwapped := listenerPairConflict(tt.second, tt.first)
			assert.Equal(t, ok, okSwapped, "conflict detection must be symmetric")
			assert.Equal(t, reason, reasonSwapped, "conflict reason must be symmetric")
		})
	}
}

func gatewayWithConflictListeners(listeners ...*gatewayv1.Listener) *gatewayv1.Gateway {
	gw := &gatewayv1.Gateway{}
	for _, l := range listeners {
		gw.Spec.Listeners = append(gw.Spec.Listeners, *l)
	}
	return gw
}

func Test_conflictedGatewayListeners(t *testing.T) {
	t.Run("non-conflicting listeners produce no entries", func(t *testing.T) {
		gw := gatewayWithConflictListeners(
			muxedListener("a", gatewayv1.HTTPProtocolType, 80, "foo.example.com"),
			muxedListener("b", gatewayv1.HTTPProtocolType, 80, "bar.example.com"),
		)
		assert.Empty(t, conflictedGatewayListeners(gw))
	})

	t.Run("identical hostname duplicate marks both listeners", func(t *testing.T) {
		gw := gatewayWithConflictListeners(
			muxedListener("a", gatewayv1.HTTPSProtocolType, 443, "foo.example.com"),
			muxedListener("b", gatewayv1.HTTPSProtocolType, 443, "foo.example.com"),
		)
		conflicts := conflictedGatewayListeners(gw)
		assert.Equal(t, gatewayv1.ListenerReasonHostnameConflict, conflicts["a"].reason)
		assert.Equal(t, gatewayv1.ListenerReasonHostnameConflict, conflicts["b"].reason)
		assert.Contains(t, conflicts["a"].message, `listener "b"`)
		assert.Contains(t, conflicts["b"].message, `listener "a"`)
	})

	t.Run("l4 and muxed on same port mark both listeners", func(t *testing.T) {
		gw := gatewayWithConflictListeners(
			l4Listener("a", gatewayv1.TCPProtocolType, 80),
			muxedListener("b", gatewayv1.HTTPProtocolType, 80, "foo.example.com"),
		)
		conflicts := conflictedGatewayListeners(gw)
		assert.Equal(t, gatewayv1.ListenerReasonProtocolConflict, conflicts["a"].reason)
		assert.Equal(t, gatewayv1.ListenerReasonProtocolConflict, conflicts["b"].reason)
	})

	t.Run("https and tls passthrough overlap keeps existing message", func(t *testing.T) {
		gw := gatewayWithConflictListeners(
			muxedListener("https", gatewayv1.HTTPSProtocolType, 443, "api.example.test"),
			tlsPassthroughListener("tls-passthrough", 443, "api.example.test"),
		)
		conflicts := conflictedGatewayListeners(gw)
		assert.Equal(t, gatewayv1.ListenerReasonProtocolConflict, conflicts["https"].reason)
		assert.Equal(t,
			`Listener conflicts with listener "tls-passthrough": same port 443 has overlapping HTTPS and TLS passthrough hostnames.`,
			conflicts["https"].message)
	})
}

func Test_acceptedListeners(t *testing.T) {
	t.Run("later listener loses against an accepted listener", func(t *testing.T) {
		accepted := &acceptedListeners{}
		accepted.accept(*muxedListener("gw-https", gatewayv1.HTTPSProtocolType, 443, "*.example.com"))

		reason := accepted.checkConflict(*tlsPassthroughListener("ls-tls", 443, "foo.example.com"))
		assert.Equal(t, gatewayv1.ListenerReasonProtocolConflict, reason)
	})

	t.Run("distinct hostname on the same protocol is accepted", func(t *testing.T) {
		accepted := &acceptedListeners{}
		accepted.accept(*muxedListener("first", gatewayv1.HTTPProtocolType, 80, "foo.example.com"))

		reason := accepted.checkConflict(*muxedListener("second", gatewayv1.HTTPProtocolType, 80, "bar.example.com"))
		assert.Empty(t, string(reason))
	})
}

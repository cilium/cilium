// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"math/rand/v2"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProxyID(t *testing.T) {
	id := ProxyID(123, true, "TCP", uint16(8080), ParserTypeHTTP, "")
	require.Equal(t, "123:ingress:TCP:8080:http:", id)
	endpointID, ingress, protocol, port, parser, listener, err := ParseProxyID(id)
	require.Equal(t, uint16(123), endpointID)
	require.True(t, ingress)
	require.Equal(t, "TCP", protocol)
	require.Equal(t, uint16(8080), port)
	require.Empty(t, listener)
	require.Equal(t, ParserTypeHTTP, parser)
	require.NoError(t, err)

	id = ProxyID(321, false, "TCP", uint16(80), ParserTypeCRD, "myListener")
	require.Equal(t, "321:egress:TCP:80:crd:myListener", id)
	endpointID, ingress, protocol, port, parser, listener, err = ParseProxyID(id)
	require.Equal(t, uint16(321), endpointID)
	require.False(t, ingress)
	require.Equal(t, "TCP", protocol)
	require.Equal(t, uint16(80), port)
	require.Equal(t, "myListener", listener)
	require.Equal(t, ParserTypeCRD, parser)
	require.NoError(t, err)

	require.NotEqual(t,
		ProxyID(123, false, "TCP", 443, ParserTypeHTTP, ""),
		ProxyID(123, false, "TCP", 443, ParserTypeTLS, ""))

}

func BenchmarkProxyID(b *testing.B) {
	id := uint16(rand.IntN(65536))
	port := uint16(rand.IntN(65536))
	want := strconv.FormatUint(uint64(id), 10) + ":ingress:TCP:" +
		strconv.FormatUint(uint64(port), 10) + ":http:"

	b.ReportAllocs()
	for b.Loop() {
		proxyID := ProxyID(id, true, "TCP", port, ParserTypeHTTP, "")
		if proxyID != want {
			b.Fatalf("ProxyID() = %q, want %q", proxyID, want)
		}
		if _, _, _, _, _, _, err := ParseProxyID(proxyID); err != nil {
			b.Fatalf("ParseProxyID(%q): %s", proxyID, err)
		}
	}
}

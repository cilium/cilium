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
	id := uint16(rand.IntN(65535))
	port := uint16(rand.IntN(65535))

	b.ReportAllocs()
	for range 1000 {
		b.StartTimer()
		proxyID := ProxyID(id, true, "TCP", port, ParserTypeHTTP, "")
		if proxyID != strconv.FormatUint(uint64(id), 10)+":ingress:TCP:"+strconv.FormatUint(uint64(port), 10)+":http:" {
			b.Failed()
		}
		_, _, _, _, _, _, err := ParseProxyID(proxyID)
		if err != nil {
			b.Failed()
		}
		b.StopTimer()
	}
}

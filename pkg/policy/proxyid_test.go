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
	id := ProxyID(123, true, "TCP", uint16(8080), "")
	require.Equal(t, id, "123:ingress:TCP:8080:")
	endpointID, ingress, protocol, port, listener, err := ParseProxyID(id)
	require.Equal(t, uint16(123), endpointID)
	require.True(t, ingress)
	require.Equal(t, "TCP", protocol)
	require.Equal(t, uint16(8080), port)
	require.Equal(t, "", listener)
	require.NoError(t, err)

	id = ProxyID(321, false, "TCP", uint16(80), "myListener")
	require.Equal(t, id, "321:egress:TCP:80:myListener")
	endpointID, ingress, protocol, port, listener, err = ParseProxyID(id)
	require.Equal(t, uint16(321), endpointID)
	require.Equal(t, false, ingress)
	require.Equal(t, "TCP", protocol)
	require.Equal(t, uint16(80), port)
	require.Equal(t, "myListener", listener)
	require.NoError(t, err)
}

func BenchmarkProxyID(b *testing.B) {
	id := uint16(rand.IntN(65535))
	port := uint16(rand.IntN(65535))

	b.ReportAllocs()
	for i := 0; i < 1000; i++ {
		b.StartTimer()
		proxyID := ProxyID(id, true, "TCP", port, "")
		if proxyID != strconv.FormatInt(int64(id), 10)+"ingress:TCP:8080:" {
			b.Failed()
		}
		_, _, _, _, _, err := ParseProxyID(proxyID)
		if err != nil {
			b.Failed()
		}
		b.StopTimer()
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"math/rand"
	"strconv"
	"testing"

	. "github.com/cilium/checkmate"
)

func (s *PolicyTestSuite) TestProxyID(c *C) {
	id := ProxyID(123, true, "TCP", uint16(8080))
	c.Assert("123:ingress:TCP:8080", Equals, id)
	endpointID, ingress, protocol, port, err := ParseProxyID(id)
	c.Assert(endpointID, Equals, uint16(123))
	c.Assert(ingress, Equals, true)
	c.Assert(protocol, Equals, "TCP")
	c.Assert(port, Equals, uint16(8080))
	c.Assert(err, IsNil)
}

func BenchmarkProxyID(b *testing.B) {
	r := rand.New(rand.NewSource(42))
	id := uint16(r.Intn(65535))
	port := uint16(r.Intn(65535))

	b.ReportAllocs()
	for i := 0; i < 1000; i++ {
		b.StartTimer()
		proxyID := ProxyID(id, true, "TCP", port)
		if proxyID != strconv.FormatInt(int64(id), 10)+"ingress:TCP:8080" {
			b.Failed()
		}
		_, _, _, _, err := ParseProxyID(proxyID)
		if err != nil {
			b.Failed()
		}
		b.StopTimer()
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"net"
	"testing"

	. "github.com/cilium/checkmate"
)

func Test(t *testing.T) { TestingT(t) }

type MTUSuite struct{}

var _ = Suite(&MTUSuite{})

func (m *MTUSuite) TestNewConfiguration(c *C) {
	// Add routes with no encryption or tunnel
	conf := NewConfiguration(0, false, false, false, 0, nil)
	c.Assert(conf.GetDeviceMTU(), Not(Equals), 0)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU())

	// Add routes with no encryption or tunnel and set MTU
	conf = NewConfiguration(0, false, false, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU())

	// Add routes with tunnel
	conf = NewConfiguration(0, false, true, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-TunnelOverhead)

	// Add routes with tunnel and set MTU
	conf = NewConfiguration(0, false, true, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-TunnelOverhead)

	// Add routes with encryption and set MTU using standard 128bit, larger 256bit and smaller 96bit ICVlen keys
	conf = NewConfiguration(16, true, false, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-EncryptionIPsecOverhead)

	conf = NewConfiguration(32, true, false, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-(EncryptionIPsecOverhead+16))

	conf = NewConfiguration(12, true, false, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-(EncryptionIPsecOverhead-4))

	// Add routes with encryption and tunnels using standard 128bit, larger 256bit and smaller 96bit ICVlen keys
	conf = NewConfiguration(16, true, true, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-(TunnelOverhead+EncryptionIPsecOverhead))

	conf = NewConfiguration(32, true, true, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-(TunnelOverhead+EncryptionIPsecOverhead+16))

	conf = NewConfiguration(32, true, true, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-(TunnelOverhead+EncryptionIPsecOverhead+16))

	// Add routes with wireguard enabled
	conf = NewConfiguration(32, false, false, true, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-WireguardOverhead)

	conf = NewConfiguration(32, false, true, true, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-WireguardOverhead)

	testIP1 := net.IPv4(0, 0, 0, 0)
	testIP2 := net.IPv4(127, 0, 0, 1)
	result, _ := getMTUFromIf(testIP1)
	c.Assert(result, Equals, 0)

	conf = NewConfiguration(0, true, true, false, 1400, testIP1)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)

	conf = NewConfiguration(0, true, true, false, 0, testIP1)
	c.Assert(conf.GetDeviceMTU(), Equals, 1500)

	// Assuming loopback interface always exists and has mtu=65536
	conf = NewConfiguration(0, true, true, false, 0, testIP2)
	c.Assert(conf.GetDeviceMTU(), Equals, 65536)
}

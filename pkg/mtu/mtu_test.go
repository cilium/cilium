// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package mtu

import (
	"net"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type MTUSuite struct{}

var _ = Suite(&MTUSuite{})

func (m *MTUSuite) TestNewConfiguration(c *C) {
	// Add routes with no encryption or tunnel
	conf := NewConfiguration(0, false, false, 0, nil)
	c.Assert(conf.GetDeviceMTU(), Not(Equals), 0)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU())

	// Add routes with no encryption or tunnel and set MTU
	conf = NewConfiguration(0, false, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU())

	// Add routes with tunnel
	conf = NewConfiguration(0, false, true, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-TunnelOverhead)

	// Add routes with tunnel and set MTU
	conf = NewConfiguration(0, false, true, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-TunnelOverhead)

	// Add routes with encryption and set MTU using standard 128bit, larger 256bit and smaller 96bit ICVlen keys
	conf = NewConfiguration(16, true, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-EncryptionIPsecOverhead)

	conf = NewConfiguration(32, true, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-(EncryptionIPsecOverhead+16))

	conf = NewConfiguration(12, true, false, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-(EncryptionIPsecOverhead-4))

	// Add routes with encryption and tunnels using standard 128bit, larger 256bit and smaller 96bit ICVlen keys
	conf = NewConfiguration(16, true, true, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-(TunnelOverhead+EncryptionIPsecOverhead))

	conf = NewConfiguration(32, true, true, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-(TunnelOverhead+EncryptionIPsecOverhead+16))

	conf = NewConfiguration(32, true, true, 1400, nil)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)
	c.Assert(conf.GetRouteMTU(), Equals, conf.GetDeviceMTU()-(TunnelOverhead+EncryptionIPsecOverhead+16))

	testIP1 := net.IPv4(0, 0, 0, 0)
	testIP2 := net.IPv4(127, 0, 0, 1)
	result, _ := getMTUFromIf(testIP1)
	c.Assert(result, Equals, 0)

	conf = NewConfiguration(0, true, true, 1400, testIP1)
	c.Assert(conf.GetDeviceMTU(), Equals, 1400)

	conf = NewConfiguration(0, true, true, 0, testIP1)
	c.Assert(conf.GetDeviceMTU(), Equals, 1500)

	// Assuming loopback interface always exists and has mtu=65536
	conf = NewConfiguration(0, true, true, 0, testIP2)
	c.Assert(conf.GetDeviceMTU(), Equals, 65536)
}

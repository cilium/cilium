// Copyright 2018-2019 Authors of Cilium
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

// +build privileged_tests

package eppolicymap

import (
	"fmt"
	"net"
	"os"
	"testing"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type EPPolicyMapTestSuite struct{}

var _ = Suite(&EPPolicyMapTestSuite{})

func (e *EPPolicyMapTestSuite) SetUpTest(c *C) {
	MapName = "unit_test_ep_to_policy"
	innerMapName = "unit_test_ep_policy_inner_map"
	err := bpf.ConfigureResourceLimits()
	c.Assert(err, IsNil)
}

func (e *EPPolicyMapTestSuite) TearDownTest(c *C) {
	os.Remove(MapName)
	os.Remove(innerMapName)
}

func (e *EPPolicyMapTestSuite) TestCreateEPPolicy(c *C) {
	bpf.CheckOrMountFS("")
	CreateEPPolicyMap()
}

func (e *EPPolicyMapTestSuite) TestWriteEndpoint(c *C) {
	option.Config.SockopsEnable = true
	bpf.CheckOrMountFS("")
	keys := make([]*lxcmap.EndpointKey, 1)
	many := make([]*lxcmap.EndpointKey, 256)
	fd, err := bpf.CreateMap(bpf.MapTypeHash,
		uint32(unsafe.Sizeof(policymap.PolicyKey{})),
		uint32(unsafe.Sizeof(policymap.PolicyEntry{})), 1024, 0, 0,
		"ep-policy-inner-map")
	c.Assert(err, IsNil)

	keys[0] = lxcmap.NewEndpointKey(net.ParseIP("1.2.3.4"))
	for i := 0; i < 256; i++ {
		ip := net.ParseIP("1.2.3." + fmt.Sprint(i))
		many[i] = lxcmap.NewEndpointKey(ip)
	}

	CreateEPPolicyMap()
	err = writeEndpoint(keys, fd)
	c.Assert(err, Not(IsNil))
	err = writeEndpoint(many, fd)
	c.Assert(err, Not(IsNil))
}

// We allow calls into WriteEndpoint with invalid fd allowing users of the
// API to avoid doing if enabled { WriteEndpoint() } and simply passing
// in invalid fd in if its disabled.
func (e *EPPolicyMapTestSuite) TestWriteEndpointFails(c *C) {
	option.Config.SockopsEnable = true
	bpf.CheckOrMountFS("")
	keys := make([]*lxcmap.EndpointKey, 1)
	_, err := bpf.CreateMap(bpf.MapTypeHash,
		uint32(unsafe.Sizeof(policymap.PolicyKey{})),
		uint32(unsafe.Sizeof(policymap.PolicyEntry{})), 1024, 0, 0,
		"ep-policy-inner-map")
	c.Assert(err, IsNil)

	keys[0] = lxcmap.NewEndpointKey(net.ParseIP("1.2.3.4"))
	CreateEPPolicyMap()
	err = writeEndpoint(keys, -1)
	c.Assert(err, Not(IsNil))
}

func (e *EPPolicyMapTestSuite) TestWriteEndpointDisabled(c *C) {
	option.Config.SockopsEnable = false
	bpf.CheckOrMountFS("")
	keys := make([]*lxcmap.EndpointKey, 1)
	fd, err := bpf.CreateMap(bpf.MapTypeHash,
		uint32(unsafe.Sizeof(policymap.PolicyKey{})),
		uint32(unsafe.Sizeof(policymap.PolicyEntry{})), 1024, 0, 0,
		"ep-policy-inner-map")
	c.Assert(err, IsNil)

	keys[0] = lxcmap.NewEndpointKey(net.ParseIP("1.2.3.4"))
	CreateEPPolicyMap()
	err = writeEndpoint(keys, fd)
	c.Assert(err, IsNil)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eppolicymap

import (
	"fmt"
	"net"
	"os"
	"testing"
	"unsafe"

	. "gopkg.in/check.v1"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type EPPolicyMapTestSuite struct{}

var _ = Suite(&EPPolicyMapTestSuite{})

func (e *EPPolicyMapTestSuite) SetUpTest(c *C) {
	testutils.PrivilegedCheck(c)

	MapName = "unit_test_ep_to_policy"
	innerMapName = "unit_test_ep_policy_inner_map"
	err := rlimit.RemoveMemlock()
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
		innerMapName)
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
		innerMapName)
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
		innerMapName)
	c.Assert(err, IsNil)

	keys[0] = lxcmap.NewEndpointKey(net.ParseIP("1.2.3.4"))
	CreateEPPolicyMap()
	err = writeEndpoint(keys, fd)
	c.Assert(err, IsNil)
}

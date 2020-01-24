// Copyright 2019 Authors of Cilium
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

package mock

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/ipam"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type MockSuite struct{}

var _ = check.Suite(&MockSuite{})

func (e *MockSuite) TestMock(c *check.C) {
	api := NewAPI([]*ipam.Subnet{{ID: "s-1", AvailableAddresses: 100}}, []*ipam.VirtualNetwork{{ID: "v-1"}}, []*types.SecurityGroup{{ID: "sg-1"}})
	c.Assert(api, check.Not(check.IsNil))

	eniID1, _, err := api.CreateNetworkInterface(context.TODO(), 8, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)

	eniID2, _, err := api.CreateNetworkInterface(context.TODO(), 8, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)

	_, err = api.AttachNetworkInterface(context.TODO(), 0, "i-1", eniID1)
	c.Assert(err, check.IsNil)

	_, ok := api.enis["i-1"][eniID1]
	c.Assert(ok, check.Equals, true)

	_, err = api.AttachNetworkInterface(context.TODO(), 1, "i-1", eniID2)
	c.Assert(err, check.IsNil)

	_, ok = api.enis["i-1"][eniID1]
	c.Assert(ok, check.Equals, true)
	_, ok = api.enis["i-1"][eniID2]
	c.Assert(ok, check.Equals, true)

	err = api.DeleteNetworkInterface(context.TODO(), eniID1)
	c.Assert(err, check.IsNil)

	err = api.DeleteNetworkInterface(context.TODO(), eniID1)
	c.Assert(err, check.Not(check.IsNil))

	err = api.DeleteNetworkInterface(context.TODO(), eniID2)
	c.Assert(err, check.IsNil)

	_, ok = api.enis["i-1"][eniID1]
	c.Assert(ok, check.Equals, false)
	_, ok = api.enis["i-1"][eniID2]
	c.Assert(ok, check.Equals, false)
}

func (e *MockSuite) TestSetMockError(c *check.C) {
	api := NewAPI([]*ipam.Subnet{}, []*ipam.VirtualNetwork{}, []*types.SecurityGroup{})
	c.Assert(api, check.Not(check.IsNil))

	mockError := errors.New("error")

	api.SetMockError(CreateNetworkInterface, mockError)
	_, _, err := api.CreateNetworkInterface(context.TODO(), 8, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(AttachNetworkInterface, mockError)
	_, err = api.AttachNetworkInterface(context.TODO(), 0, "i-1", "e-1")
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(DeleteNetworkInterface, mockError)
	err = api.DeleteNetworkInterface(context.TODO(), "e-1")
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(AssignPrivateIpAddresses, mockError)
	err = api.AssignPrivateIpAddresses(context.TODO(), "e-1", 10)
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(UnassignPrivateIpAddresses, mockError)
	err = api.UnassignPrivateIpAddresses(context.TODO(), "e-1", []string{"10.0.0.10", "10.0.0.11"})
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(ModifyNetworkInterface, mockError)
	err = api.ModifyNetworkInterface(context.TODO(), "e-1", "a-1", true)
	c.Assert(err, check.Equals, mockError)
}

func (e *MockSuite) TestSetDelay(c *check.C) {
	api := NewAPI([]*ipam.Subnet{}, []*ipam.VirtualNetwork{}, []*types.SecurityGroup{})
	c.Assert(api, check.Not(check.IsNil))

	api.SetDelay(AllOperations, time.Second)
	c.Assert(api.delays[CreateNetworkInterface], check.Equals, time.Second)
	c.Assert(api.delays[DeleteNetworkInterface], check.Equals, time.Second)
	c.Assert(api.delays[ModifyNetworkInterface], check.Equals, time.Second)
	c.Assert(api.delays[AttachNetworkInterface], check.Equals, time.Second)
	c.Assert(api.delays[AssignPrivateIpAddresses], check.Equals, time.Second)
	c.Assert(api.delays[UnassignPrivateIpAddresses], check.Equals, time.Second)
}

func (e *MockSuite) TestSetLimiter(c *check.C) {
	api := NewAPI([]*ipam.Subnet{{ID: "s-1", AvailableAddresses: 100}}, []*ipam.VirtualNetwork{{ID: "v-1"}}, []*types.SecurityGroup{{ID: "sg-1"}})
	c.Assert(api, check.Not(check.IsNil))

	api.SetLimiter(10.0, 2)
	_, _, err := api.CreateNetworkInterface(context.TODO(), 8, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
}

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
	"errors"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/aws/types"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type MockSuite struct{}

var _ = check.Suite(&MockSuite{})

func (e *MockSuite) TestMock(c *check.C) {
	api := NewAPI([]*types.Subnet{{ID: "s-1", AvailableAddresses: 100}})
	c.Assert(api, check.Not(check.IsNil))

	eniID1, err := api.CreateNetworkInterface(8, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)

	eniID2, err := api.CreateNetworkInterface(8, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)

	_, err = api.AttachNetworkInterface(0, "i-1", eniID1)
	c.Assert(err, check.IsNil)

	eni := api.GetENI("i-1", 0)
	c.Assert(eni, check.Not(check.IsNil))

	enis := api.GetENIs("i-1")
	c.Assert(len(enis), check.Equals, 1)

	_, err = api.AttachNetworkInterface(1, "i-1", eniID2)
	c.Assert(err, check.IsNil)

	eni = api.GetENI("i-1", 1)
	c.Assert(eni, check.Not(check.IsNil))

	enis = api.GetENIs("i-1")
	c.Assert(len(enis), check.Equals, 2)

	err = api.DeleteNetworkInterface(eniID1)
	c.Assert(err, check.IsNil)

	err = api.DeleteNetworkInterface(eniID1)
	c.Assert(err, check.Not(check.IsNil))

	err = api.DeleteNetworkInterface(eniID2)
	c.Assert(err, check.IsNil)

	c.Assert(api.GetENI("i-1", 0), check.IsNil)

	c.Assert(api.GetSubnet("s-1"), check.Not(check.IsNil))
	c.Assert(api.GetSubnet("s-2"), check.IsNil)
}

func (e *MockSuite) TestSetMockError(c *check.C) {
	api := NewAPI([]*types.Subnet{})
	c.Assert(api, check.Not(check.IsNil))

	mockError := errors.New("error")

	api.SetMockError(CreateNetworkInterface, mockError)
	_, err := api.CreateNetworkInterface(8, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(AttachNetworkInterface, mockError)
	_, err = api.AttachNetworkInterface(0, "i-1", "e-1")
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(DeleteNetworkInterface, mockError)
	err = api.DeleteNetworkInterface("e-1")
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(AssignPrivateIpAddresses, mockError)
	err = api.AssignPrivateIpAddresses("e-1", 10)
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(ModifyNetworkInterface, mockError)
	err = api.ModifyNetworkInterface("e-1", "a-1", true)
	c.Assert(err, check.Equals, mockError)
}

func (e *MockSuite) TestSetDelay(c *check.C) {
	api := NewAPI([]*types.Subnet{})
	c.Assert(api, check.Not(check.IsNil))

	api.SetDelay(AllOperations, time.Second)
	c.Assert(api.delays[CreateNetworkInterface], check.Equals, time.Second)
	c.Assert(api.delays[DeleteNetworkInterface], check.Equals, time.Second)
	c.Assert(api.delays[ModifyNetworkInterface], check.Equals, time.Second)
	c.Assert(api.delays[AttachNetworkInterface], check.Equals, time.Second)
	c.Assert(api.delays[AssignPrivateIpAddresses], check.Equals, time.Second)
}

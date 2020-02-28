// Copyright 2019-2020 Authors of Cilium
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
	"testing"
	"time"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type MockSuite struct{}

var _ = check.Suite(&MockSuite{})

func (e *MockSuite) TestMock(c *check.C) {
	api := NewMockMetrics()
	api.ObserveAPICall("DescribeNetworkInterfaces", "success", 2.0)
	c.Assert(api.APICall("DescribeNetworkInterfaces", "success"), check.Equals, 2.0)
	api.ObserveRateLimit("DescribeNetworkInterfaces", time.Second)
	api.ObserveRateLimit("DescribeNetworkInterfaces", time.Second)
	c.Assert(api.RateLimit("DescribeNetworkInterfaces"), check.Equals, 2*time.Second)
}

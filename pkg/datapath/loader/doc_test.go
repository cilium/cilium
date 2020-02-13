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

package loader

import (
	"testing"

	"github.com/cilium/cilium/pkg/node"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type LoaderTestSuite struct{}

var _ = Suite(&LoaderTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *LoaderTestSuite) SetUpTest(c *C) {
	node.InitDefaultPrefix("")
	node.SetInternalIPv4(templateIPv4)
	node.SetIPv4Loopback(templateIPv4)
}

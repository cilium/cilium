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

// +build privileged_tests

package probes

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ProbesPrivTestSuite struct{}

var _ = Suite(&ProbesPrivTestSuite{})

func (s *ProbesPrivTestSuite) TestSystemConfigProbes(c *C) {
	pm := NewProbeManager()
	err := pm.SystemConfigProbes()
	c.Assert(err, IsNil)
}

func (s *ProbesPrivTestSuite) TestMapTypes(c *C) {
	pm := NewProbeManager()
	mapTypes := pm.GetMapTypes()
	c.Assert(mapTypes, NotNil)
}

func (s *ProbesPrivTestSuite) TestHelpers(c *C) {
	pm := NewProbeManager()
	_, ok := pm.GetHelpers("sched_act")["bpf_map_lookup_elem"]
	c.Assert(ok, Equals, true)
}

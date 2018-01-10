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

package workloads

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type WorkloadsTestSuite struct{}

var _ = Suite(&WorkloadsTestSuite{})

func (w *WorkloadsTestSuite) TestParseConfig(c *C) {
	// Test if user options overwrites defaults values
	err := ParseConfig([]string{string(Auto)}, map[string]string{string(Docker): "foo"})
	c.Assert(err, IsNil)

	opts := GetRuntimeOpt(Docker)
	c.Assert(opts, Not(IsNil))
	c.Assert(opts.Endpoint, Equals, "foo")

	// Test if default options are set
	containerRuntimes = make(map[containerRuntimeType]containerRuntimeOpts)
	err = ParseConfig([]string{string(Auto)}, map[string]string{})
	c.Assert(err, IsNil)

	opts = GetRuntimeOpt(Docker)
	c.Assert(opts, Not(IsNil))
	c.Assert(opts.Endpoint, Equals, GetRuntimeDefaultOpt(Docker).Endpoint)

	// Test if with none any options are set
	containerRuntimes = make(map[containerRuntimeType]containerRuntimeOpts)
	err = ParseConfig([]string{string(None), string(Auto)}, map[string]string{string(Docker): "foo"})
	c.Assert(err, IsNil)

	opts = GetRuntimeOpt(Docker)
	c.Assert(opts, IsNil)

	// Test invalid runtime
	containerRuntimes = make(map[containerRuntimeType]containerRuntimeOpts)
	err = ParseConfig([]string{"foo"}, map[string]string{"foo": "foo"})
	c.Assert(err, Not(IsNil))
}

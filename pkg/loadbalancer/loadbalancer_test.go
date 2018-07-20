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

package loadbalancer

import (
	"testing"

	"gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type TypesSuite struct{}

var _ = check.Suite(&TypesSuite{})

func (s *TypesSuite) TestIsK8ServiceExternal(c *check.C) {
	si := K8sServiceInfo{}

	c.Assert(si.IsExternal(), check.Equals, true)

	si.Selector = map[string]string{"l": "v"}
	c.Assert(si.IsExternal(), check.Equals, false)
}

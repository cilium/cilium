// Copyright 2017 Authors of Cilium
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

package version

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type VersionSuite struct {
}

var _ = Suite(&VersionSuite{})

func (vs *VersionSuite) TestStructIsSet(c *C) {
	output := "Cilium 0.13.90 7330b8d Sun, 12 Nov 2017 13:34:43 +0900 go version go1.8.3 linux/amd64"
	cver := versionFrom(output)

	c.Assert(cver.Version, Equals, "0.13.90")
	c.Assert(cver.Revision, Equals, "7330b8d")
	c.Assert(cver.Arch, Equals, "linux/amd64")
}

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

package versioncheck

import (
	"testing"

	go_version "github.com/hashicorp/go-version"
	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type VersionCheckTestSuite struct{}

var _ = Suite(&VersionCheckTestSuite{})

func (vc *VersionCheckTestSuite) TestMustCompile(c *C) {
	// Bumping go-version revision after 4fe82ae3040f removes
	// comparision between constrains that are not "pre-releases" and
	// versions that are "pre-releases".
	constraint := MustCompile(">= 1.11.0")
	ver, err := go_version.NewVersion("1.14.7-eks-e9b1d0")
	c.Assert(err, IsNil)
	c.Assert(ver.Prerelease(), checker.Equals, "eks-e9b1d0")
	c.Assert(ver.Segments(), checker.DeepEquals, []int{1, 14, 7})
	c.Assert(constraint.String(), checker.Equals, ">= 1.11.0")
	c.Assert(constraint.Check(ver), checker.Equals, true)
}

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

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type VersionCheckTestSuite struct{}

var _ = Suite(&VersionCheckTestSuite{})

func (vc *VersionCheckTestSuite) TestMustCompile(c *C) {
	tests := []struct {
		name       string
		version    string
		constraint string
		want       bool
	}{
		{
			name:       "1",
			version:    "1.17.0-alpha.2",
			constraint: ">=1.17.0",
			want:       false,
		},
		{
			name:       "2",
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			name:       "3",
			version:    "1.17.0-alpha.2",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			name:       "4",
			version:    "1.16.3-beta.0",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			name:       "5",
			version:    "1.17.0-alpha.2",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			name:       "6",
			version:    "1.16.3-beta.0",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			name:       "7",
			version:    "1.17.0",
			constraint: ">=1.17.0",
			want:       true,
		},
		{
			name:       "8",
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.14.7",
			want:       true,
		},
		{
			name:       "9",
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.14.6",
			want:       true,
		},
		{
			name:       "10",
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.14.8",
			want:       false,
		},
		{
			name:       "11",
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.13.0",
			want:       true,
		},
		{
			name:       "12",
			version:    "1.17.0-alpha.2",
			constraint: ">=1.13.0",
			want:       true,
		},
		{
			name:       "13",
			version:    "1.16.3-beta.0",
			constraint: ">=1.13.0",
			want:       true,
		},
		{
			name:       "14",
			version:    "1.16.0-rc.2",
			constraint: ">=1.16.0",
			want:       false,
		},
		{
			name:       "15",
			version:    "1.17.0-alpha.2",
			constraint: ">=1.17.0-alpha.1",
			want:       true,
		},
	}
	for _, t := range tests {
		ver, err := Version(t.version)
		c.Assert(err, IsNil, Commentf("Test Name %s", t.name))
		constraint, err := Compile(t.constraint)
		c.Assert(err, IsNil, Commentf("Test Name %s", t.name))
		c.Assert(constraint(ver), checker.Equals, t.want, Commentf("Test Name %s", t.name))
	}
}

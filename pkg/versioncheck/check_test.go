// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package versioncheck

import (
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type VersionCheckTestSuite struct{}

var _ = Suite(&VersionCheckTestSuite{})

func (vc *VersionCheckTestSuite) TestMustCompile(c *C) {
	tests := []struct {
		version    string
		constraint string
		want       bool
	}{
		{
			version:    "1.17.0-alpha.2",
			constraint: ">=1.17.0",
			want:       false,
		},
		{
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			version:    "1.17.0-alpha.2",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			version:    "1.16.3-beta.0",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			version:    "1.17.0-alpha.2",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			version:    "1.16.3-beta.0",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			version:    "1.17.0",
			constraint: ">=1.17.0",
			want:       true,
		},
		{
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.14.7",
			want:       true,
		},
		{
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.14.6",
			want:       true,
		},
		{
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.14.8",
			want:       false,
		},
		{
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.13.0",
			want:       true,
		},
		{
			version:    "1.17.0-alpha.2",
			constraint: ">=1.13.0",
			want:       true,
		},
		{
			version:    "1.16.3-beta.0",
			constraint: ">=1.13.0",
			want:       true,
		},
		{
			version:    "1.16.0-rc.2",
			constraint: ">=1.16.0",
			want:       false,
		},
		{
			version:    "1.17.0-alpha.2",
			constraint: ">=1.17.0-alpha.1",
			want:       true,
		},
		{
			version:    "1.14.0-snapshot.0",
			constraint: ">=1.13.0",
			want:       true,
		},
		{
			version:    "1.14.0-snapshot.1",
			constraint: ">=1.14.0-snapshot.0",
			want:       true,
		},
		{
			version:    "1.14.0-snapshot.0",
			constraint: ">=1.14.0",
			want:       false,
		},
	}
	for _, t := range tests {
		ver, err := Version(t.version)
		c.Assert(err, IsNil, Commentf("version %s, constraint %s", t.version, t.constraint))
		constraint, err := Compile(t.constraint)
		c.Assert(err, IsNil, Commentf("version %s, constraint", t.version, t.constraint))
		c.Assert(constraint(ver), checker.Equals, t.want, Commentf("version %s, constraint %s", t.version, t.constraint))
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package version

import (
	"runtime"
	"testing"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type VersionSuite struct{}

var _ = Suite(&VersionSuite{})

func (vs *VersionSuite) TestStructIsSet(c *C) {
	var versionDataList = []struct {
		in  string
		out CiliumVersion
	}{
		{
			"0.11.90 774ecd3 2018-01-09T22:32:37+01:00 go version go1.8.3 linux/amd64",
			CiliumVersion{
				Version:          "0.11.90",
				Revision:         "774ecd3",
				GoRuntimeVersion: "go1.8.3",
				Arch:             "linux/amd64",
				AuthorDate:       "2018-01-09T22:32:37+01:00",
			},
		},
		{
			"0.11.90 774ecd3 2018-01-09T22:32:37+01:00 go version go1.9 someArch/i8726",
			CiliumVersion{
				Version:          "0.11.90",
				Revision:         "774ecd3",
				GoRuntimeVersion: "go1.9",
				Arch:             "someArch/i8726",
				AuthorDate:       "2018-01-09T22:32:37+01:00",
			},
		},
		{
			"278.121.290 774ecd3 2018-01-09T22:32:37+01:00 go version go2522.2520.25251 windows/amd64",
			CiliumVersion{
				Version:          "278.121.290",
				Revision:         "774ecd3",
				GoRuntimeVersion: "go2522.2520.25251",
				Arch:             "windows/amd64",
				AuthorDate:       "2018-01-09T22:32:37+01:00",
			},
		},
		{
			"0.13.90 7330b8d 2018-01-09T22:32:37+01:00 go version go1.8.3 linux/arm",
			CiliumVersion{
				Version:          "0.13.90",
				Revision:         "7330b8d",
				GoRuntimeVersion: "go1.8.3",
				Arch:             "linux/arm",
				AuthorDate:       "2018-01-09T22:32:37+01:00",
			},
		},
		// Unformatted string should return empty struct
		{
			"0.13.90 7330b8d linux/arm",
			CiliumVersion{
				Version:          "",
				Revision:         "",
				GoRuntimeVersion: "",
				Arch:             "",
				AuthorDate:       "",
			},
		},
	}

	for _, tt := range versionDataList {
		cver := FromString(tt.in)
		c.Assert(cver.Version, Equals, tt.out.Version)
		c.Assert(cver.Revision, Equals, tt.out.Revision)
		c.Assert(cver.GoRuntimeVersion, Equals, tt.out.GoRuntimeVersion)
		c.Assert(cver.Arch, Equals, tt.out.Arch)
		c.Assert(cver.AuthorDate, Equals, tt.out.AuthorDate)
	}
}

func (vs *VersionSuite) TestVersionArchMatchesGOARCH(c *C) {
	// var ciliumVersion is not set in tests, thus Version does not contain the cilium version,
	// just check that GOOS/GOARCH are reported correctly, see #13122.
	c.Assert(Version, Matches, ".* "+runtime.GOOS+"/"+runtime.GOARCH)
}

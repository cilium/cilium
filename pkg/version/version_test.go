// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package version

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStructIsSet(t *testing.T) {
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
		require.Equal(t, tt.out.Version, cver.Version)
		require.Equal(t, tt.out.Revision, cver.Revision)
		require.Equal(t, tt.out.GoRuntimeVersion, cver.GoRuntimeVersion)
		require.Equal(t, tt.out.Arch, cver.Arch)
		require.Equal(t, tt.out.AuthorDate, cver.AuthorDate)
	}
}

func TestVersionArchMatchesGOARCH(t *testing.T) {
	// var ciliumVersion is not set in tests, thus Version does not contain the cilium version,
	// just check that GOOS/GOARCH are reported correctly, see #13122.
	require.Regexp(t, ".* "+runtime.GOOS+"/"+runtime.GOARCH, Version)
}

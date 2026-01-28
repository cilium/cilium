// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func Test_protoToFileInfo(t *testing.T) {
	uu := map[string]struct {
		in *flow.FileInfo
		e  FileInfo
	}{
		"empty": {},

		"full": {
			in: &flow.FileInfo{
				Name: "f1",
				Line: 42,
			},
			e: FileInfo{
				Name: "f1",
				Line: 42,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, protoToFileInfo(u.in))
		})
	}
}

func TestFileInfo_isEmpty(t *testing.T) {
	uu := map[string]struct {
		f    FileInfo
		want bool
	}{
		"empty": {
			want: true,
		},

		"partial": {
			f: FileInfo{
				Name: "f1",
			},
		},

		"full": {
			f: FileInfo{
				Name: "f1",
				Line: 42,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.want, u.f.isEmpty())
		})
	}
}

func TestFileInfo_toProto(t *testing.T) {
	uu := map[string]struct {
		f   FileInfo
		out *flow.FileInfo
	}{
		"empty": {},

		"full": {
			f: FileInfo{
				Name: "f1",
				Line: 42,
			},
			out: &flow.FileInfo{
				Name: "f1",
				Line: 42,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.out, u.f.toProto())
		})
	}
}

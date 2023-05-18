// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"os"
	"path/filepath"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

func (s *EndpointSuite) TestMoveNewFilesTo(c *check.C) {
	oldDir := c.MkDir()
	newDir := c.MkDir()
	f1, err := os.CreateTemp(oldDir, "")
	c.Assert(err, check.IsNil)
	f2, err := os.CreateTemp(oldDir, "")
	c.Assert(err, check.IsNil)
	f3, err := os.CreateTemp(newDir, "")
	c.Assert(err, check.IsNil)

	// Copy the same file in both directories to make sure the same files
	// are not moved from the old directory into the new directory.
	err = os.WriteFile(filepath.Join(oldDir, "foo"), []byte(""), os.FileMode(0644))
	c.Assert(err, check.IsNil)
	err = os.WriteFile(filepath.Join(newDir, "foo"), []byte(""), os.FileMode(0644))
	c.Assert(err, check.IsNil)

	compareDir := func(dir string, wantedFiles []string) {
		files, err := os.ReadDir(dir)
		c.Assert(err, check.IsNil)
		filesNames := make([]string, 0, len(wantedFiles))
		for _, file := range files {
			filesNames = append(filesNames, file.Name())
		}
		c.Assert(wantedFiles, checker.DeepEquals, filesNames)
	}

	type args struct {
		oldDir string
		newDir string
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		wantOldDir []string
		wantNewDir []string
	}{
		{
			name: "copying from one directory to the other",
			args: args{
				oldDir: oldDir,
				newDir: newDir,
			},
			wantErr: false,
			wantOldDir: []string{
				"foo",
			},
			wantNewDir: []string{
				f1.Name(),
				f2.Name(),
				f3.Name(),
				"foo",
			},
		},
	}
	for _, tt := range tests {
		if err := moveNewFilesTo(tt.args.oldDir, tt.args.newDir); (err != nil) != tt.wantErr {
			c.Assert(err != nil, check.Equals, tt.wantErr)
			compareDir(tt.args.oldDir, tt.wantOldDir)
			compareDir(tt.args.newDir, tt.wantNewDir)
		}
	}
}

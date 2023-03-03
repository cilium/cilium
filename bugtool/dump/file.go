// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/cilium/cilium/bugtool/cmd"
)

// File implements a Task that will copy a file into a dump.
type File struct {
	base               `mapstructure:",squash"`
	Src                string
	ExcludeObjectFiles string `mapstructure:"exclude_object_files"`
}

func (f *File) Validate(ctx context.Context) error {
	if err := f.validate(); err != nil {
		return fmt.Errorf("invalid file %q: %w", f.Name, err)
	}
	return nil
}

func NewFile(Src string) *File {
	return &File{
		base: base{
			Name: strings.ReplaceAll(Src, "/", "_"),
			Kind: "File",
		},
		Src: Src,
	}
}

func (f *File) WithExcludeObjFiles(pattern string) *File {
	nf := *f
	nf.ExcludeObjectFiles = pattern
	return &nf
}

func (f *File) Run(ctx context.Context, runtime Context) error {
	if f.Src == "" {
		return fmt.Errorf("source file/dir cannot be empty")
	}
	return runtime.Submit(f.Identifier(), func(_ context.Context) error {
		out, err := exec.CommandContext(ctx, "cp", "-r", f.Src, runtime.Dir()).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to copy %q: %w, %s", runtime.Dir(), err, out)
		}

		if f.ExcludeObjectFiles != "" {
			cmd.RemoveObjectFiles(runtime.Dir(), f.ExcludeObjectFiles)
		}
		return nil
	})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"context"
	"fmt"
	"os/exec"
	"path"
	"strings"
)

// File implements a Task that will copy a file into a dump.
type File struct {
	Base      `mapstructure:",squash"`
	Src       string
	MissingOk bool
	recursive bool
}

func (f *File) Validate(ctx context.Context) error {
	if err := f.validate(); err != nil {
		return fmt.Errorf("invalid file %q: %w", f.Name, err)
	}
	return nil
}

func NewFile(Src string) *File {
	return &File{
		Base: Base{
			Name: "file:" + strings.ReplaceAll(Src, "/", "_"),
			Kind: "File",
		},
		Src:       Src,
		MissingOk: false,
	}
}

func (f *File) WithRecursive() *File {
	nf := *f
	nf.recursive = true
	return &nf
}

func (c *File) Run(ctx context.Context, runtime Context) error {
	if c.Src == "" {
		return fmt.Errorf("source file/dir cannot be empty")
	}
	_, name := path.Split(c.Src)
	return runtime.Submit(name, func(_ context.Context) error {
		out, err := exec.CommandContext(ctx, "cp", "-r", c.Src).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to copy %q: %w, %s", runtime.Dir(), err, out)
		}
		return nil
	})
}

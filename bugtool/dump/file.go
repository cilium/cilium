// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
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
	return runtime.Submit(ctx, f.Identifier(), func(_ context.Context) error {
		out, err := exec.CommandContext(ctx, "cp", "-r", f.Src, runtime.Dir()).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to copy %q: %w, %s", runtime.Dir(), err, out)
		}

		if f.ExcludeObjectFiles != "" {
			log.Debugf("%s excluding object files: %q", f.Identifier(), f.ExcludeObjectFiles)
			removeObjectFiles(runtime.Dir(), f.ExcludeObjectFiles)
		}
		return nil
	})
}

func removeObjectFiles(cmdDir, pattern string) {
	// Remove object files for each endpoint. Endpoints directories are in the
	// state directory and have numerical names.
	rmFunc := func(path string) {
		matches, err := filepath.Glob(path)
		if err != nil {
			log.Errorf("Failed to exclude object files: %s", err)
		}
		for _, m := range matches {
			err = os.Remove(m)
			if err != nil {
				log.Errorf("Failed to exclude object file: %s", err)
			}
		}
	}

	path := filepath.Join(cmdDir, pattern)
	rmFunc(path)
}

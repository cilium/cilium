// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"io"
	"os"
)

// TaskFile implements a WriteCloser, but if nothing is written to the file
// at when Close is invoked then the file is deleted.
type TaskFile struct {
	f       string
	written int
	w       io.WriteCloser
}

func (f *TaskFile) Write(p []byte) (n int, err error) {
	n, err = f.w.Write(p)
	f.written += n
	return
}

func (f *TaskFile) Close() error {
	if err := f.w.Close(); err != nil {
		return err
	}
	if f.written == 0 {
		return os.Remove(f.f)
	}
	return nil
}

func createTaskFile(filename string, fd io.WriteCloser) *TaskFile {
	return &TaskFile{f: filename, w: fd}
}

// Copyright 2018 Authors of Cilium
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

package files

import (
	"fmt"
	"io"
	"os"
)

// FileWithCleanup is a wrapper for os.File which removes the file on closing
// when no bytes were written.
type FileWithCleanup struct {
	// path string
	n int
	*os.File
}

// Close closes the File, rendering it unusable for I/O. On files that support
// SetDeadline, any pending I/O operations will be canceled and return
// immediately with an error. If no bytes were written to the file, it will be
// removed after closing.
func (f *FileWithCleanup) Close() error {
	if err := f.File.Close(); err != nil {
		return fmt.Errorf("could not close file %s: %s", f.File.Name(), err)
	}
	if f.n == 0 {
		if err := os.Remove(f.Name()); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("could not remove file %s: %s", f.File.Name(), err)
		}
	}
	return nil
}

// Sync commits the current contents of the file to stable storage. Typically,
// this means flushing the file system's in-memory copy of recently written
// data to disk.
func (f *FileWithCleanup) Sync() error {
	if err := f.File.Sync(); err != nil {
		return fmt.Errorf("could not sync file %s: %s", f.File.Name(), err)
	}
	return nil
}

// Write writes len(b) bytes to the File. It returns the number of bytes
// written and an error, if any. Write returns a non-nil error when n != len(b).
func (f *FileWithCleanup) Write(data []byte) (int, error) {
	n, err := f.File.Write(data)
	if err != nil {
		return n, fmt.Errorf("could not write to file %s: %s", f.File.Name(), err)
	}
	f.n += n
	return n, nil
}

// WriteString is like Write, but writes the contents of string s rather than
// a slice of bytes.
func (f *FileWithCleanup) WriteString(s string) (int, error) {
	return f.Write([]byte(s))
}

// OpenOrCreate opens the named file for reading and writing. If the file does
// not exist, it gets created.
func OpenOrCreate(path string) (*FileWithCleanup, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	return &FileWithCleanup{n: 0, File: f}, nil
}

// Copy copies the file from source to destination. If there is any file in the
// destination path, it will be removed.
func Copy(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	os.Remove(dest)

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

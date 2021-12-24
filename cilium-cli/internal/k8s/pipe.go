// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package k8s

import (
	"errors"
	"fmt"
	"io"
)

// CopyOptions have the data required to perform the copy operation
type CopyOptions struct {
	// Maximum number of retries, -1 for unlimited retries.
	MaxTries int

	// ReaderFunc is the actual implementation for reading file content
	ReadFunc ReadFunc
}

// ReadFunc function is to support reading content from given offset till EOF.
// The content will be written to io.Writer.
type ReadFunc func(offset uint64, writer io.Writer) error

// CopyPipe struct is simple implementation to support copy files with retry.
type CopyPipe struct {
	Options *CopyOptions

	Reader *io.PipeReader
	Writer *io.PipeWriter

	bytesRead uint64
	retries   int
}

func newPipe(option *CopyOptions) *CopyPipe {
	p := new(CopyPipe)
	p.Options = option
	p.startReadFrom(0)
	return p
}

func (t *CopyPipe) startReadFrom(offset uint64) {
	t.Reader, t.Writer = io.Pipe()
	go func() {
		var err error
		defer func() {
			// close with error here to make sure any read operation with Pipe Reader will have return the same error
			// otherwise, by default, EOF will be returned.
			_ = t.Writer.CloseWithError(err)
		}()
		err = t.Options.ReadFunc(offset, t.Writer)
	}()
}

// Read function is to satisfy io.Reader interface.
// This is simple implementation to support resuming copy in case of there is any temporary issue (e.g. networking)
func (t *CopyPipe) Read(p []byte) (int, error) {
	n, err := t.Reader.Read(p)
	if err != nil {
		// If EOF error happens, just bubble it up, no retry is required.
		if errors.Is(err, io.EOF) {
			return n, err
		}

		// Check if the number of retries is already exhausted
		if t.Options.MaxTries >= 0 && t.retries >= t.Options.MaxTries {
			return n, fmt.Errorf("dropping out copy after %d retries: %w", t.retries, err)
		}

		// Perform retry
		if t.bytesRead == 0 {
			t.startReadFrom(t.bytesRead)
		} else {
			t.startReadFrom(t.bytesRead + 1)
		}
		t.retries++
		return 0, nil
	}
	t.bytesRead += uint64(n)
	return n, err
}

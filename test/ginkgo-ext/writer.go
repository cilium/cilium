// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ginkgoext

import (
	"bytes"
	"io"

	"github.com/cilium/cilium/pkg/lock"
)

// A Writer is a struct that has a variable-sized `bytes.Buffer` and one
// outWriter(`io.writer`) to stream data
type Writer struct {
	Buffer    *bytes.Buffer
	outWriter io.Writer
	lock      *lock.Mutex
}

// NewWriter creates and initializes a Writer with a empty Buffer and the given
// outWriter
func NewWriter(outWriter io.Writer) *Writer {
	return &Writer{
		Buffer:    &bytes.Buffer{},
		outWriter: outWriter,
		lock:      &lock.Mutex{},
	}
}

// Write appends the contents of b to the buffer and outWriter, growing the
// buffer as needed. The return value n is the length of p; err is always nil.
// If the buffer becomes too large, Write will panic with ErrTooLarge.
func (w *Writer) Write(b []byte) (n int, err error) {
	w.lock.Lock()
	defer w.lock.Unlock()
	n, err = w.Buffer.Write(b)
	if err != nil {
		return n, err
	}
	return w.outWriter.Write(b)
}

// Reset resets the buffer to be empty,
func (w *Writer) Reset() {
	w.lock.Lock()
	defer w.lock.Unlock()
	w.Buffer.Reset()
}

// Bytes returns a slice based on buffer.Bytes()
func (w *Writer) Bytes() []byte {
	w.lock.Lock()
	defer w.lock.Unlock()
	return w.Buffer.Bytes()
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"bytes"

	"github.com/cilium/cilium/pkg/lock"
)

// A Buffer is a variable-sized buffer of bytes with Read and Write methods.
// The zero value for Buffer is an empty buffer ready to use.
type Buffer struct {
	buffer bytes.Buffer
	mutex  lock.Mutex
}

// Write appends the contents of p to the buffer, growing the buffer as
// needed. The return value n is the length of p; err is always nil. If the
// buffer becomes too large, Write will panic with ErrTooLarge.
func (buf *Buffer) Write(p []byte) (n int, err error) {
	buf.mutex.Lock()
	r, err := buf.buffer.Write(p)
	buf.mutex.Unlock()
	return r, err
}

// String returns the contents of the unread portion of the buffer
// as a string. If the Buffer is a nil pointer, it returns "<nil>".
//
// To build strings more efficiently, see the strings.Builder type.
func (buf *Buffer) String() string {
	buf.mutex.Lock()
	r := buf.buffer.String()
	buf.mutex.Unlock()
	return r
}

// Reset resets the buffer to be empty,
// but it retains the underlying storage for use by future writes.
// Reset is the same as Truncate(0).
func (buf *Buffer) Reset() {
	buf.mutex.Lock()
	buf.buffer.Reset()
	buf.mutex.Unlock()
}

// Len returns the number of bytes of the unread portion of the buffer;
// b.Len() == len(b.Bytes()).
func (buf *Buffer) Len() int {
	buf.mutex.Lock()
	r := buf.buffer.Len()
	buf.mutex.Unlock()
	return r
}

// Bytes returns a slice of length b.Len() holding the unread portion of the buffer.
// The slice is valid for use only until the next buffer modification (that is,
// only until the next call to a method like Read, Write, Reset, or Truncate).
// The slice aliases the buffer content at least until the next buffer modification,
// so immediate changes to the slice will affect the result of future reads.
func (buf *Buffer) Bytes() []byte {
	buf.mutex.Lock()
	r := buf.buffer.Bytes()
	buf.mutex.Unlock()
	return r
}

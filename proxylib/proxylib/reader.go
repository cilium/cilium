// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxylib

import (
	"io"
)

type Reader struct {
	buf       [][]byte // buffer that shrinks as data is being read
	read      int      // Number of byte read since last reset
	endStream bool     // connection is known to end (in this direction) after the current input
}

func NewReader(input [][]byte, endStream bool) Reader {
	return Reader{
		buf:       input,
		endStream: endStream,
	}
}

func (r *Reader) Reset() int {
	read := r.read
	r.read = 0
	return read
}

func (r *Reader) Length() int {
	length := 0
	for i := 0; i < len(r.buf); i++ {
		length += len(r.buf[i])
	}
	return length
}

func (r *Reader) PeekFull(p []byte) (n int, err error) {
	n = 0
	slice := 0
	index := 0
	for n < len(p) && slice < len(r.buf) {
		bytes := len(r.buf[slice][index:])
		nc := copy(p[n:], r.buf[slice][index:])
		if nc == bytes {
			// next slice please
			slice++
			index = 0
		} else {
			// move ahead in the same slice
			index += nc
		}
		n += nc
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (r *Reader) Read(p []byte) (n int, err error) {
	n = 0
	for n < len(p) && len(r.buf) > 0 {
		nc := copy(p[n:], r.buf[0])
		if nc == len(r.buf[0]) {
			// next slice please
			r.buf = r.buf[1:]
		} else {
			// move ahead in the same slice
			r.buf[0] = r.buf[0][nc:]
		}
		n += nc
	}
	if n == 0 {
		return 0, io.EOF
	}
	r.read += n
	return n, nil
}

// Skip bytes in input, or exhaust the input.
func (r *Reader) AdvanceInput(bytes int) {
	for bytes > 0 && len(r.buf) > 0 {
		rem := len(r.buf[0]) // this much data left in the first slice
		if bytes < rem {
			r.buf[0] = r.buf[0][bytes:] // skip 'bytes' bytes
			return
		} else { // go to the beginning of the next unit
			bytes -= rem
			r.buf = r.buf[1:] // may result in an empty slice
		}
	}
}

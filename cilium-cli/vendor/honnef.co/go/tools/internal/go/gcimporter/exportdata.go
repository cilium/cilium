// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is a copy of $GOROOT/src/go/internal/gcimporter/exportdata.go.

// This file implements FindExportData.

package gcimporter

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
)

func readGopackHeader(r io.Reader) (name string, size int, err error) {
	// See $GOROOT/include/ar.h.
	hdr := make([]byte, 16+12+6+6+8+10+2)
	_, err = io.ReadFull(r, hdr)
	if err != nil {
		return
	}
	// leave for debugging
	if false {
		fmt.Printf("header: %s", hdr)
	}
	s := strings.TrimSpace(string(hdr[16+12+6+6+8:][:10]))
	size, err = strconv.Atoi(s)
	if err != nil || hdr[len(hdr)-2] != '`' || hdr[len(hdr)-1] != '\n' {
		err = fmt.Errorf("invalid archive header")
		return
	}
	name = strings.TrimSpace(string(hdr[:16]))
	return
}

// findExportData positions the reader r at the beginning of the
// export data section of an underlying GC-created object/archive
// file by reading from it. The reader must be positioned at the
// start of the file before calling this function. The hdr result
// is the string before the export data, either "$$" or "$$B".
//
func findExportData(r *bufio.Reader) (hdr string, length int, err error) {
	// Read first line to make sure this is an object file.
	line, err := r.ReadSlice('\n')
	if err != nil {
		err = fmt.Errorf("can't find export data (%v)", err)
		return
	}

	if string(line) == "!<arch>\n" {
		// Archive file. Scan to __.PKGDEF.
		var name string
		if name, length, err = readGopackHeader(r); err != nil {
			return
		}

		// First entry should be __.PKGDEF.
		if name != "__.PKGDEF" {
			err = fmt.Errorf("go archive is missing __.PKGDEF")
			return
		}

		// Read first line of __.PKGDEF data, so that line
		// is once again the first line of the input.
		if line, err = r.ReadSlice('\n'); err != nil {
			err = fmt.Errorf("can't find export data (%v)", err)
			return
		}
		length -= len(line)
	}

	// Now at __.PKGDEF in archive or still at beginning of file.
	// Either way, line should begin with "go object ".
	if !strings.HasPrefix(string(line), "go object ") {
		err = fmt.Errorf("not a Go object file")
		return
	}

	// Skip over object header to export data.
	// Begins after first line starting with $$.
	for line[0] != '$' {
		if line, err = r.ReadSlice('\n'); err != nil {
			err = fmt.Errorf("can't find export data (%v)", err)
			return
		}
		length -= len(line)
	}
	hdr = string(line)

	return
}

func GetExportData(r io.ReadSeeker, b []byte) ([]byte, error) {
	br := bufio.NewReader(r)
	_, length, err := findExportData(br)
	if err != nil {
		return nil, err
	}
	if _, err := r.Seek(-int64(br.Buffered()), io.SeekCurrent); err != nil {
		return nil, err
	}
	if length > 0 {
		if cap(b) >= length {
			b = b[:length]
		} else {
			b = make([]byte, length)
		}
		_, err := io.ReadFull(r, b)
		return b, err
	} else {
		return ioutil.ReadAll(r)
	}
}

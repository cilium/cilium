// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package utils

import (
	"context"
	"io"
	"sync"
)

// CtrlCReader implements a simple Reader/Closer that returns Ctrl-C and EOF
// on Read() after it has been closed, and nothing before it.
type CtrlCReader struct {
	ctx       context.Context
	closeOnce sync.Once
	closed    chan struct{}
}

// NewCtrlCReader returns a new CtrlCReader instance
func NewCtrlCReader(ctx context.Context) *CtrlCReader {
	return &CtrlCReader{
		ctx:    ctx,
		closed: make(chan struct{}),
	}
}

// Read implements io.Reader.
// Blocks until we are done.
func (cc *CtrlCReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-cc.closed:
		// Graceful close, EOF without any data
		return 0, io.EOF
	case <-cc.ctx.Done():
		// Context cancelled, send Ctrl-C/Ctrl-D
		p[0] = byte(3) // Ctrl-C
		if len(p) > 1 {
			// Add Ctrl-D for the case Ctrl-C alone is ineffective.
			// We skip this in the odd case where the buffer is too small.
			p[1] = byte(4) // Ctrl-D
			return 2, io.EOF
		}
		return 1, io.EOF
	}
}

// Close implements io.Closer. Note that we do not return an error on
// second close, not do we wait for the close to have any effect.
func (cc *CtrlCReader) Close() error {
	cc.closeOnce.Do(func() {
		close(cc.closed)
	})
	return nil
}

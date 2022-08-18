// Copyright (c) 2020-2021 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package testutil

import (
	"go.uber.org/zap/zapcore"
)

// TestingT is a subset of the testing.T interface.
type TestingT interface {
	Logf(string, ...interface{})
}

// WriteSyncer is a zapcore.WriteSyncer that writes to the provided test
// logger.
type WriteSyncer struct{ T TestingT }

var _ zapcore.WriteSyncer = WriteSyncer{}

// Write writes the provided bytes to the underlying TestingT.
func (w WriteSyncer) Write(bs []byte) (int, error) {
	w.T.Logf("%s", bs)
	return len(bs), nil
}

// Sync is a no-op.
func (WriteSyncer) Sync() error { return nil }

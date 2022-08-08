// Copyright (c) 2019-2021 Uber Technologies, Inc.
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

package fxtest

import (
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/fx/internal/fxlog"
	"go.uber.org/fx/internal/testutil"
)

// NewTestLogger returns an fxlog.Logger that logs to the testing TB.
func NewTestLogger(t TB) fxevent.Logger {
	return fxlog.DefaultLogger(testutil.WriteSyncer{T: t})
}

type testPrinter struct {
	TB
}

// NewTestPrinter returns a fx.Printer that logs to the testing TB.
func NewTestPrinter(t TB) fx.Printer {
	return &testPrinter{t}
}

func (p *testPrinter) Printf(format string, args ...interface{}) {
	p.Logf(format, args...)
}

// Copyright (c) 2019 Uber Technologies, Inc.
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

package fxreflect

import (
	"fmt"
	"io"
	"runtime"
	"strings"
)

// Frame holds information about a single frame in the call stack.
type Frame struct {
	// Unique, package path-qualified name for the function of this call
	// frame.
	Function string

	// File and line number of our location in the frame.
	//
	// Note that the line number does not refer to where the function was
	// defined but where in the function the next call was made.
	File string
	Line int
}

func (f Frame) String() string {
	// This takes the following forms.
	//  (path/to/file.go)
	//  (path/to/file.go:42)
	//  path/to/package.MyFunction
	//  path/to/package.MyFunction (path/to/file.go)
	//  path/to/package.MyFunction (path/to/file.go:42)

	var sb strings.Builder
	sb.WriteString(f.Function)
	if len(f.File) > 0 {
		if sb.Len() > 0 {
			sb.WriteRune(' ')
		}
		fmt.Fprintf(&sb, "(%v", f.File)
		if f.Line > 0 {
			fmt.Fprintf(&sb, ":%d", f.Line)
		}
		sb.WriteRune(')')
	}

	if sb.Len() == 0 {
		return "unknown"
	}

	return sb.String()
}

const _defaultCallersDepth = 8

// Stack is a stack of call frames.
//
// Formatted with %v, the output is in a single-line, in the form,
//
//   foo/bar.Baz() (path/to/foo.go:42); bar/baz.Qux() (bar/baz/qux.go:12); ...
//
// Formatted with %+v, the output is in the form,
//
//   foo/bar.Baz()
//   	path/to/foo.go:42
//   bar/baz.Qux()
//   	bar/baz/qux.go:12
type Stack []Frame

// Returns a single-line, semi-colon representation of a Stack. For a
// multi-line representation, use %+v.
func (fs Stack) String() string {
	items := make([]string, len(fs))
	for i, f := range fs {
		items[i] = f.String()
	}
	return strings.Join(items, "; ")
}

// Format implements fmt.Formatter to handle "%+v".
func (fs Stack) Format(w fmt.State, c rune) {
	if !w.Flag('+') {
		// Without %+v, fall back to String().
		io.WriteString(w, fs.String())
		return
	}

	for _, f := range fs {
		fmt.Fprintln(w, f.Function)
		fmt.Fprintf(w, "\t%v:%v\n", f.File, f.Line)
	}
}

// CallerName returns the name of the first caller in this stack that isn't
// owned by the Fx library.
func (fs Stack) CallerName() string {
	for _, f := range fs {
		if shouldIgnoreFrame(f) {
			continue
		}
		return f.Function
	}
	return "n/a"
}

// CallerStack returns the call stack for the calling function, up to depth frames
// deep, skipping the provided number of frames, not including Callers itself.
//
// If zero, depth defaults to 8.
func CallerStack(skip, depth int) Stack {
	if depth <= 0 {
		depth = _defaultCallersDepth
	}

	pcs := make([]uintptr, depth)

	// +2 to skip this frame and runtime.Callers.
	n := runtime.Callers(skip+2, pcs)
	pcs = pcs[:n] // truncate to number of frames actually read

	result := make([]Frame, 0, n)
	frames := runtime.CallersFrames(pcs)
	for f, more := frames.Next(); more; f, more = frames.Next() {
		result = append(result, Frame{
			Function: sanitize(f.Function),
			File:     f.File,
			Line:     f.Line,
		})
	}
	return result
}

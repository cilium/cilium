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

package dig

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"go.uber.org/dig/internal/digreflect"
)

type cycleErrPathEntry struct {
	Key  key
	Func *digreflect.Func
}

type errCycleDetected struct {
	Path  []cycleErrPathEntry
	scope *Scope
}

var _ digError = errCycleDetected{}

func (e errCycleDetected) Error() string {
	// We get something like,
	//
	//   [scope "foo"]
	//   func(*bar) *foo provided by "path/to/package".NewFoo (path/to/file.go:42)
	//   	depends on func(*baz) *bar provided by "another/package".NewBar (somefile.go:1)
	//   	depends on func(*foo) baz provided by "somepackage".NewBar (anotherfile.go:2)
	//   	depends on func(*bar) *foo provided by "path/to/package".NewFoo (path/to/file.go:42)
	//
	b := new(bytes.Buffer)

	if name := e.scope.name; len(name) > 0 {
		fmt.Fprintf(b, "[scope %q]\n", name)
	}
	for i, entry := range e.Path {
		if i > 0 {
			b.WriteString("\n\tdepends on ")
		}
		fmt.Fprintf(b, "%v provided by %v", entry.Key, entry.Func)
	}
	return b.String()
}

func (e errCycleDetected) writeMessage(w io.Writer, v string) {
	fmt.Fprint(w, e.Error())
}

func (e errCycleDetected) Format(w fmt.State, c rune) {
	formatError(e, w, c)
}

// IsCycleDetected returns a boolean as to whether the provided error indicates
// a cycle was detected in the container graph.
func IsCycleDetected(err error) bool {
	return errors.As(err, &errCycleDetected{})
}

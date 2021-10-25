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
	"fmt"

	"go.uber.org/dig/internal/digreflect"
)

type cycleEntry struct {
	Key  key
	Func *digreflect.Func
}

type errCycleDetected struct {
	Path []cycleEntry
}

func (e errCycleDetected) Error() string {
	// We get something like,
	//
	//   foo provided by "path/to/package".NewFoo (path/to/file.go:42)
	//   	depends on bar provided by "another/package".NewBar (somefile.go:1)
	//   	depends on baz provided by "somepackage".NewBar (anotherfile.go:2)
	//   	depends on foo provided by "path/to/package".NewFoo (path/to/file.go:42)
	//
	b := new(bytes.Buffer)

	for i, entry := range e.Path {
		if i > 0 {
			b.WriteString("\n\tdepends on ")
		}
		fmt.Fprintf(b, "%v provided by %v", entry.Key, entry.Func)
	}
	return b.String()
}

// IsCycleDetected returns a boolean as to whether the provided error indicates
// a cycle was detected in the container graph.
func IsCycleDetected(err error) bool {
	_, ok := RootCause(err).(errCycleDetected)
	return ok
}

func verifyAcyclic(c containerStore, n provider, k key) error {
	visited := make(map[key]struct{})
	err := detectCycles(n, c, []cycleEntry{
		{Key: k, Func: n.Location()},
	}, visited)
	if err != nil {
		err = errf("this function introduces a cycle", err)
	}
	return err
}

func detectCycles(n provider, c containerStore, path []cycleEntry, visited map[key]struct{}) error {
	var err error
	walkParam(n.ParamList(), paramVisitorFunc(func(param param) bool {
		if err != nil {
			return false
		}

		var (
			k         key
			providers []provider
		)
		switch p := param.(type) {
		case paramSingle:
			k = key{name: p.Name, t: p.Type}
			if _, ok := visited[k]; ok {
				// We've already checked the dependencies for this type.
				return false
			}
			providers = c.getValueProviders(p.Name, p.Type)
		case paramGroupedSlice:
			// NOTE: The key uses the element type, not the slice type.
			k = key{group: p.Group, t: p.Type.Elem()}
			if _, ok := visited[k]; ok {
				// We've already checked the dependencies for this type.
				return false
			}
			providers = c.getGroupProviders(p.Group, p.Type.Elem())
		default:
			// Recurse for non-edge params.
			return true
		}

		entry := cycleEntry{Func: n.Location(), Key: k}

		if len(path) > 0 {
			// Only mark a key as visited if path exists, i.e. this is not the
			// first iteration through the c.verifyAcyclic() check. Otherwise the
			// early exit from checking visited above will short circuit the
			// cycle check below.
			visited[k] = struct{}{}

			// If it exists, the first element of path is the new addition to the
			// graph, therefore it must be in any cycle that exists, assuming
			// verifyAcyclic has been run for every previous Provide.
			//
			// Alternatively, if deferAcyclicVerification was set and detectCycles
			// is only being called before the first Invoke, each node in the
			// graph will be tested as the first element of the path, so any
			// cycle that exists is guaranteed to trip the following condition.
			if path[0].Key == k {
				err = errCycleDetected{Path: append(path, entry)}
				return false
			}
		}

		for _, n := range providers {
			if e := detectCycles(n, c, append(path, entry), visited); e != nil {
				err = e
				return false
			}
		}

		return true
	}))

	return err
}

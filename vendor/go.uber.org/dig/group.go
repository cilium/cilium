// Copyright (c) 2020 Uber Technologies, Inc.
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
	"fmt"
	"io"
	"strings"
)

const (
	_groupTag = "group"
)

type group struct {
	Name    string
	Flatten bool
	Soft    bool
}

type errInvalidGroupOption struct{ Option string }

var _ digError = errInvalidGroupOption{}

func (e errInvalidGroupOption) Error() string { return fmt.Sprint(e) }

func (e errInvalidGroupOption) writeMessage(w io.Writer, v string) {
	fmt.Fprintf(w, "invalid option %q", e.Option)
}

func (e errInvalidGroupOption) Format(w fmt.State, c rune) {
	formatError(e, w, c)
}

func parseGroupString(s string) (group, error) {
	components := strings.Split(s, ",")
	g := group{Name: components[0]}
	for _, c := range components[1:] {
		switch c {
		case "flatten":
			g.Flatten = true
		case "soft":
			g.Soft = true
		default:
			return g, errInvalidGroupOption{Option: c}
		}
	}
	return g, nil
}

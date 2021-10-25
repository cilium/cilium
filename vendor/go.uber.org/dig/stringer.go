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
	"strings"
)

// String representation of the entire Container
func (c *Container) String() string {
	b := &bytes.Buffer{}
	fmt.Fprintln(b, "nodes: {")
	for k, vs := range c.providers {
		for _, v := range vs {
			fmt.Fprintln(b, "\t", k, "->", v)
		}
	}
	fmt.Fprintln(b, "}")

	fmt.Fprintln(b, "values: {")
	for k, v := range c.values {
		fmt.Fprintln(b, "\t", k, "=>", v)
	}
	for k, vs := range c.groups {
		for _, v := range vs {
			fmt.Fprintln(b, "\t", k, "=>", v)
		}
	}
	fmt.Fprintln(b, "}")

	return b.String()
}

func (n *node) String() string {
	return fmt.Sprintf("deps: %v, ctor: %v", n.paramList, n.ctype)
}

func (k key) String() string {
	if k.name != "" {
		return fmt.Sprintf("%v[name=%q]", k.t, k.name)
	}
	if k.group != "" {
		return fmt.Sprintf("%v[group=%q]", k.t, k.group)
	}
	return k.t.String()
}

func (pl paramList) String() string {
	args := make([]string, len(pl.Params))
	for i, p := range pl.Params {
		args[i] = p.String()
	}
	return fmt.Sprint(args)
}

func (sp paramSingle) String() string {
	// tally.Scope[optional] means optional
	// tally.Scope[optional, name="foo"] means named optional

	var opts []string
	if sp.Optional {
		opts = append(opts, "optional")
	}
	if sp.Name != "" {
		opts = append(opts, fmt.Sprintf("name=%q", sp.Name))
	}

	if len(opts) == 0 {
		return fmt.Sprint(sp.Type)
	}

	return fmt.Sprintf("%v[%v]", sp.Type, strings.Join(opts, ", "))
}

func (op paramObject) String() string {
	fields := make([]string, len(op.Fields))
	for i, f := range op.Fields {
		fields[i] = f.Param.String()
	}
	return strings.Join(fields, " ")
}

func (pt paramGroupedSlice) String() string {
	// io.Reader[group="foo"] refers to a group of io.Readers called 'foo'
	return fmt.Sprintf("%v[group=%q]", pt.Type.Elem(), pt.Group)
}

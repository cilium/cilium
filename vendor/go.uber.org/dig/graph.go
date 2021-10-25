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
	"io"
	"strconv"
	"text/template"

	"go.uber.org/dig/internal/dot"
)

// A VisualizeOption modifies the default behavior of Visualize.
type VisualizeOption interface {
	applyVisualizeOption(*visualizeOptions)
}

type visualizeOptions struct {
	VisualizeError error
}

type visualizeOptionFunc func(*visualizeOptions)

func (f visualizeOptionFunc) applyVisualizeOption(opts *visualizeOptions) { f(opts) }

// VisualizeError includes a visualization of the given error in the output of
// Visualize if an error was returned by Invoke or Provide.
//
//   if err := c.Provide(...); err != nil {
//     dig.Visualize(c, w, dig.VisualizeError(err))
//   }
//
// This option has no effect if the error was nil or if it didn't contain any
// information to visualize.
func VisualizeError(err error) VisualizeOption {
	return visualizeOptionFunc(func(opts *visualizeOptions) {
		opts.VisualizeError = err
	})
}

func updateGraph(dg *dot.Graph, err error) error {
	var errors []errVisualizer
	// Unwrap error to find the root cause.
	for {
		if ev, ok := err.(errVisualizer); ok {
			errors = append(errors, ev)
		}
		e, ok := err.(causer)
		if !ok {
			break
		}
		err = e.cause()
	}

	// If there are no errVisualizers included, we do not modify the graph.
	if len(errors) == 0 {
		return nil
	}

	// We iterate in reverse because the last element is the root cause.
	for i := len(errors) - 1; i >= 0; i-- {
		errors[i].updateGraph(dg)
	}

	// Remove non-error entries from the graph for readability.
	dg.PruneSuccess()

	return nil
}

var _graphTmpl = template.Must(
	template.New("DotGraph").
		Funcs(template.FuncMap{
			"quote": strconv.Quote,
		}).
		Parse(`digraph {
	rankdir=RL;
	graph [compound=true];
	{{range $g := .Groups}}
		{{- quote .String}} [{{.Attributes}}];
		{{range .Results}}
			{{- quote $g.String}} -> {{quote .String}};
		{{end}}
	{{end -}}
	{{range $index, $ctor := .Ctors}}
		subgraph cluster_{{$index}} {
			{{ with .Package }}label = {{ quote .}};
			{{ end -}}

			constructor_{{$index}} [shape=plaintext label={{quote .Name}}];
			{{with .ErrorType}}color={{.Color}};{{end}}
			{{range .Results}}
				{{- quote .String}} [{{.Attributes}}];
			{{end}}
		}
		{{range .Params}}
			constructor_{{$index}} -> {{quote .String}} [ltail=cluster_{{$index}}{{if .Optional}} style=dashed{{end}}];
		{{end}}
		{{range .GroupParams}}
			constructor_{{$index}} -> {{quote .String}} [ltail=cluster_{{$index}}];
		{{end -}}
	{{end}}
	{{range .Failed.TransitiveFailures}}
		{{- quote .String}} [color=orange];
	{{end -}}
	{{range .Failed.RootCauses}}
		{{- quote .String}} [color=red];
	{{end}}
}`))

// Visualize parses the graph in Container c into DOT format and writes it to
// io.Writer w.
func Visualize(c *Container, w io.Writer, opts ...VisualizeOption) error {
	dg := c.createGraph()

	var options visualizeOptions
	for _, o := range opts {
		o.applyVisualizeOption(&options)
	}

	if options.VisualizeError != nil {
		if err := updateGraph(dg, options.VisualizeError); err != nil {
			return err
		}
	}

	return _graphTmpl.Execute(w, dg)
}

// CanVisualizeError returns true if the error is an errVisualizer.
func CanVisualizeError(err error) bool {
	for {
		if _, ok := err.(errVisualizer); ok {
			return true
		}
		e, ok := err.(causer)
		if !ok {
			break
		}
		err = e.cause()
	}

	return false
}

func (c *Container) createGraph() *dot.Graph {
	dg := dot.NewGraph()

	for _, n := range c.nodes {
		dg.AddCtor(newDotCtor(n), n.paramList.DotParam(), n.resultList.DotResult())
	}

	return dg
}

func newDotCtor(n *node) *dot.Ctor {
	return &dot.Ctor{
		ID:      n.id,
		Name:    n.location.Name,
		Package: n.location.Package,
		File:    n.location.File,
		Line:    n.location.Line,
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"sort"
	"strings"

	"go.uber.org/dig"

	"github.com/cilium/cilium/pkg/hive/internal"
)

// provider is a set of constructors
type provider struct {
	ctors  []any
	infos  []dig.ProvideInfo
	export bool
}

func (p *provider) Apply(c container) error {
	p.infos = make([]dig.ProvideInfo, len(p.ctors))
	for i, ctor := range p.ctors {
		if err := c.Provide(ctor, dig.Export(p.export), dig.FillProvideInfo(&p.infos[i])); err != nil {
			return err
		}
	}
	return nil
}

func (p *provider) Info(container) Info {
	n := &InfoNode{}
	for i, ctor := range p.ctors {
		info := p.infos[i]
		privateSymbol := ""
		if !p.export {
			privateSymbol = "🔒️"
		}

		ctorNode := NewInfoNode(fmt.Sprintf("🚧%s %s", privateSymbol, internal.FuncNameAndLocation(ctor)))
		ctorNode.condensed = true

		var ins, outs []string
		for _, input := range info.Inputs {
			ins = append(ins, internal.TrimName(input.String()))
		}
		sort.Strings(ins)
		for _, output := range info.Outputs {
			outs = append(outs, internal.TrimName(output.String()))
		}
		sort.Strings(outs)
		if len(ins) > 0 {
			ctorNode.AddLeaf("⇨ %s", strings.Join(ins, ", "))
		}
		ctorNode.AddLeaf("⇦ %s", strings.Join(outs, ", "))
		n.Add(ctorNode)
	}
	return n
}

// Provide constructs a new cell with the given constructors.
// Constructor is any function that takes zero or more parameters and returns
// one or more values and optionally an error. For example, the following forms
// are accepted:
//
//	func() A
//	func(A, B, C) (D, error).
//
// If the constructor depends on a type that is not provided by any constructor
// the hive will fail to run with an error pointing at the missing type.
//
// A constructor can also take as parameter a structure of parameters annotated
// with `cell.In`, or return a struct annotated with `cell.Out`:
//
//	type params struct {
//		cell.In
//		Flower *Flower
//		Sun *Sun
//	}
//
//	type out struct {
//		cell.Out
//		Honey *Honey
//		Nectar *Nectar
//	}
//
//	func newBee(params) (out, error)
func Provide(ctors ...any) Cell {
	return &provider{ctors: ctors, export: true}
}

// ProvidePrivate is like Provide, but the constructed objects are only
// available within the module it is defined and nested modules.
func ProvidePrivate(ctors ...any) Cell {
	return &provider{ctors: ctors, export: false}
}

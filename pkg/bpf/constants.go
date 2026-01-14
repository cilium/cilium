// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"iter"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/datapath/config"
)

// applyConstants sets the values of BPF C runtime configurables defined using
// the DECLARE_CONFIG macro.
func applyConstants(spec *ebpf.CollectionSpec, obj any) error {
	if obj == nil {
		return nil
	}

	constants, err := config.Map(obj)
	if err != nil {
		return fmt.Errorf("converting struct to map: %w", err)
	}

	for name, value := range constants {
		constName := config.ConstantPrefix + name

		v, ok := spec.Variables[constName]
		if !ok {
			return fmt.Errorf("can't set non-existent Variable %s", name)
		}

		if v.SectionName != config.Section {
			return fmt.Errorf("can only set Cilium config variables in section %s (got %s:%s), ", config.Section, v.SectionName, name)
		}

		if err := v.Set(value); err != nil {
			return fmt.Errorf("setting Variable %s: %w", name, err)
		}
	}

	return nil
}

// iterAny returns a sequence that yields the elements of the given object if it
// is a slice, or the object itself otherwise. Nil values are never yielded.
func iterAny(obj any) iter.Seq[any] {
	return func(yield func(any) bool) {
		if obj == nil {
			return
		}

		if reflect.TypeOf(obj).Kind() != reflect.Slice {
			yield(obj)
			return
		}

		rv := reflect.ValueOf(obj)
		for i := 0; i < rv.Len(); i++ {
			v := rv.Index(i)
			if v.IsNil() {
				continue
			}
			if !yield(v.Interface()) {
				return
			}
		}
	}
}

// printConstants returns a string representation of a given consts object for
// logging purposes. Since the input can be a slice of objects, they need to be
// printed separately for struct field names to show up using %#v.
func printConstants(objs any) string {
	var frags []string
	for obj := range iterAny(objs) {
		frags = append(frags, fmt.Sprintf("%#v", obj))
	}
	return "[" + strings.Join(frags, ", ") + "]"
}

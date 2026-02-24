//go:build !windows

package gen

import (
	"cmp"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// CollectGlobalTypes finds all types which are used in the global scope.
//
// This currently includes the types of variables, map keys and values.
func CollectGlobalTypes(spec *ebpf.CollectionSpec) []btf.Type {
	var types []btf.Type

	types = collectMapTypes(types, spec.Maps)
	types = collectVariableTypes(types, spec.Variables)

	slices.SortStableFunc(types, func(a, b btf.Type) int {
		return cmp.Compare(a.TypeName(), b.TypeName())
	})

	return types
}

// collectMapTypes collects all types used by MapSpecs.
func collectMapTypes(types []btf.Type, maps map[string]*ebpf.MapSpec) []btf.Type {
	for _, m := range maps {
		if m.Key != nil && m.Key.TypeName() != "" {
			types = addType(types, m.Key)
		}

		if m.Value != nil && m.Value.TypeName() != "" {
			types = addType(types, m.Value)
		}
	}

	return types
}

// collectVariableTypes collects all types used by VariableSpecs.
func collectVariableTypes(types []btf.Type, vars map[string]*ebpf.VariableSpec) []btf.Type {
	for _, vs := range vars {
		v := vs.Type()
		if v == nil {
			continue
		}

		types = addType(types, v.Type)
	}

	return types
}

// addType adds a type to types if not already present. Types that don't need to
// be generated are not added to types.
func addType(types []btf.Type, incoming btf.Type) []btf.Type {
	incoming = selectType(incoming)
	if incoming == nil {
		return types
	}

	// Strip only the qualifiers (not typedefs) from the incoming type. Retain
	// typedefs since they carry the name of the anonymous type they point to,
	// without which we can't generate a named Go type.
	incoming = btf.QualifiedType(incoming)
	if incoming.TypeName() == "" {
		return types
	}

	exists := func(existing btf.Type) bool {
		return existing.TypeName() == incoming.TypeName()
	}
	if !slices.ContainsFunc(types, exists) {
		types = append(types, incoming)
	}
	return types
}

func selectType(t btf.Type) btf.Type {
	// Obtain a concrete type with qualifiers and typedefs stripped.
	switch ut := btf.UnderlyingType(t).(type) {
	case *btf.Struct, *btf.Union, *btf.Enum:
		return t

	// Collect the array's element type. Note: qualifiers on array-type variables
	// typically appear after the array, e.g. a const volatile int[4] is actually
	// an array of const volatile ints.
	case *btf.Array:
		return selectType(ut.Type)
	}

	return nil
}

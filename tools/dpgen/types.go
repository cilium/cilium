// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/container/set"
)

// typesOpts are the input options for the types command.
var typesOpts struct {
	goPkg string
}

const typesGoFile = "types_generated.go"

func runTypes(cmd *cobra.Command, args []string) error {
	// Enable deduplication on the builder to make all equivalent types included
	// from shared headers to become one in the BTF type blob. Without this, we
	// wouldn't be able to tell if multiple types with the same name from
	// different object files would be identical or not.
	bb, err := btf.NewBuilder(nil, &btf.BuilderOptions{Deduplicate: true})
	if err != nil {
		return fmt.Errorf("creating BTF builder: %w", err)
	}

	// Maintain an added set so we only try to render root types appearing
	// directly in maps and variables.
	added := &set.Set[string]{}

	// One dpgen -types invocation must see all ELFs to be able to merge their BTF
	// and resolve cross-references between types.
	for p := range glob(args) {
		cs, err := ebpf.LoadCollectionSpec(p)
		if err != nil {
			return fmt.Errorf("loading CollectionSpec %s: %w", p, err)
		}

		for _, spec := range sorted(cs.Maps) {
			if !needMapSpec(spec) {
				continue
			}

			if err := addMapKV(bb, added, spec); err != nil {
				return fmt.Errorf("adding KV types for map %s: %w", spec.Name, err)
			}
		}

		for _, v := range sorted(cs.Variables) {
			if err := addVariableType(bb, added, v); err != nil {
				return fmt.Errorf("adding type for variable %s: %w", v.Name, err)
			}
		}
	}

	// Pull a BTF spec out of the builder, allowing us to query the merged type
	// collection.
	spec, err := bb.Spec()
	if err != nil {
		return fmt.Errorf("building BTF spec: %w", err)
	}

	b := bytes.Buffer{}
	if err := writeHeader(&b, typesOpts.goPkg, []string{"structs"}); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	gf := btf.GoFormatter{Identifier: camelCase}
	for t := range sortedSeq(added.Members()) {
		// Look up all added root types by name to: 1. avoid emitting type decls for
		// embedded types, and 2. ensure all types with the same name deduplicated
		// into one concrete type. This lookup will fail if there are multiple
		// incompatible candidate types with the same name across objects.
		typ, err := spec.AnyTypeByName(t)
		if err != nil {
			return fmt.Errorf("getting BTF type %v: %w", t, err)
		}

		// Only include structs, unions and typedefs.
		switch typ.(type) {
		default:
			continue
		case *btf.Struct, *btf.Union, *btf.Typedef:
		}

		cName := typ.TypeName()
		goName := camelCase(cName)
		s, err := gf.TypeDeclaration(goName, typ)
		if err != nil {
			return fmt.Errorf("writing Go type declaration for %v: %w", typ, err)
		}

		b.WriteString("// " + goName + " is generated from the BPF C type " + cName + ".\n")
		b.WriteString(s)
		b.WriteString("\n\n")
	}

	formatted, err := format.Source(b.Bytes())
	if err != nil {
		return fmt.Errorf("formatting generated code: %w", err)
	}

	if err := os.WriteFile(typesGoFile, formatted, 0644); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}

	return nil
}

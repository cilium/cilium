// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"text/template"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/mitchellh/go-wordwrap"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/datapath/config/types"
)

// configOpts are the input options for the config command.
var configOpts struct {
	goPkg, typesPkg string

	embed  string
	embeds []string

	kind, outName, outFile string
}

// needUtils tracks whether any of the variables reference external types that
// require rendering a file with utility functions to the target package.
var needUtils = false

// needExternalTypes tracks whether any of the variables reference external
// types (i.e. structs or unions) that need to be rendered with `dpgen type`.
var needExternalTypes = false

func runConfig(cmd *cobra.Command, args []string) error {
	spec, err := ebpf.LoadCollectionSpec(args[0])
	if err != nil {
		return fmt.Errorf("loading spec: %w", err)
	}

	s, err := varsToStruct(spec, configOpts.outName, configOpts.kind, configOpts.typesPkg, configOpts.embeds)
	if err != nil {
		return fmt.Errorf("generating config struct: %w", err)
	}

	if needUtils {
		if err := writeUtilFile("util_generated.go", configOpts.goPkg); err != nil {
			return fmt.Errorf("writing util file: %w", err)
		}
	}

	var b bytes.Buffer
	if err := writeHeader(&b, configOpts.goPkg, nil); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	if needExternalTypes {
		if configOpts.typesPkg == "" {
			return fmt.Errorf("external types needed but types package is empty")
		}
		if err := writeImports(&b, []string{configOpts.typesPkg}); err != nil {
			return fmt.Errorf("writing imports: %w", err)
		}
	}
	if _, err := b.WriteString(s); err != nil {
		return fmt.Errorf("writing struct: %w", err)
	}
	if err := os.WriteFile(configOpts.outFile, b.Bytes(), 0644); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}

	return nil
}

//go:embed util_generated.go.tpl
var utilTpl string

// writeUtilFile writes utility functions needed by the generated code to a
// file.
func writeUtilFile(path, pkg string) error {
	tpl, err := template.New("util").Parse(utilTpl)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()

	if err := tpl.Execute(f, struct {
		Package string
	}{
		pkg,
	}); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	return nil
}

// varsToStruct generates a Go struct from the configuration variables in the
// CollectionSpec.
func varsToStruct(spec *ebpf.CollectionSpec, name, kind, typesPkg string, embeds []string) (string, error) {
	type field struct {
		comment  string
		goName   string
		cName    string
		typ      string
		defValue string
	}

	kind = "kind:" + kind

	fields := make([]field, 0, len(spec.Variables))

	for n, v := range spec.Variables {
		// Only consider variables in a specific config section to avoid interfering
		// with unrelated objects.
		if v.SectionName != types.ConstantSection {
			continue
		}

		// DECLARE_CONFIG prefixes the variable name with a well-known prefix to
		// avoid collisions with other variables with common names.
		n = strings.TrimPrefix(n, types.ConstantPrefix)

		if v.Type == nil {
			return "", fmt.Errorf("variable %s has no type information, was the ELF built without BTF?", n)
		}

		// Skip variables that don't have the requested kind.
		tags := v.Type.Tags
		if !slices.Contains(tags, kind) {
			continue
		}

		// Pop the kind tag from the list of tags, we don't want to render it out
		// to the config struct.
		tags = slices.DeleteFunc(tags, func(s string) bool { return s == kind })

		if len(tags) == 0 || tags[0] == "" {
			return "", fmt.Errorf("variable %s has no doc comment", n)
		}

		typ, err := btfVarGoTypeName(v.Type, typesPkg)
		if err != nil {
			return "", fmt.Errorf("variable %s: getting Go type: %w", n, err)
		}

		comment, err := tagsToComment(tags)
		if err != nil {
			return "", fmt.Errorf("variable %s: converting tags to comments: %w", n, err)
		}

		defValue, err := varGoValue(v, typesPkg)
		if err != nil {
			return "", fmt.Errorf("variable %s: getting default Go value: %w", n, err)
		}

		fields = append(fields, field{comment, camelCase(n), n, typ, goValueLiteral(defValue)})
	}

	slices.SortStableFunc(fields, func(a, b field) int {
		return strings.Compare(a.goName, b.goName)
	})

	var b strings.Builder

	// Render a Go type definition for a configuration struct.
	comment := fmt.Sprintf(`%s is a configuration struct for a Cilium datapath object.

Warning: do not instantiate directly! Always use [New%s] to ensure the default values configured in the ELF are honored.`, name, name)
	b.WriteString(wrapString(comment, "// "))

	fmt.Fprintf(&b, "type %s struct {\n", name)

	for _, f := range fields {
		b.WriteString(f.comment)
		fmt.Fprintf(&b, "\t%s %s `%s:\"%s\"`\n", f.goName, f.typ, types.ConstantTag, f.cName)
	}

	if len(embeds) > 0 {
		if len(fields) > 0 {
			b.WriteString("\n")
		}
		for _, e := range embeds {
			fmt.Fprintf(&b, "\t%s\n", e)
		}
	}
	b.WriteString("}\n")

	// Render a constructor with default values set using ASSIGN_CONFIG.
	var params []string
	for _, e := range embeds {
		params = append(params, fmt.Sprintf("%s %s", strings.ToLower(e), e))
	}

	fmt.Fprintf(&b, "\nfunc New%s(%s) *%s {\n", name, strings.Join(params, ", "), name)
	fmt.Fprintf(&b, "\treturn &%s{", name)
	var vals []string
	for _, f := range fields {
		vals = append(vals, f.defValue)
	}
	for _, e := range embeds {
		vals = append(vals, strings.ToLower(e))
	}
	b.WriteString(join(vals))
	b.WriteString("}\n")
	b.WriteString("}\n")

	return b.String(), nil
}

// varGoValue returns the Go value of a variable as an any.
func varGoValue(v *ebpf.VariableSpec, typesPkg string) (any, error) {
	switch t := btf.UnderlyingType(v.Type.Type).(type) {
	case *btf.Int:
		switch t.Encoding {
		case btf.Signed:
			switch t.Size {
			case 1:
				return getValue[int8](v)
			case 2:
				return getValue[int16](v)
			case 4:
				return getValue[int32](v)
			case 8:
				return getValue[int64](v)
			default:
				return nil, fmt.Errorf("unsupported signed integer size %d", t.Size)
			}
		case btf.Unsigned:
			switch t.Size {
			case 1:
				return getValue[uint8](v)
			case 2:
				return getValue[uint16](v)
			case 4:
				return getValue[uint32](v)
			case 8:
				return getValue[uint64](v)
			default:
				return nil, fmt.Errorf("unsupported unsigned integer size %d", t.Size)
			}
		case btf.Bool:
			return getValue[bool](v)
		default:
			return nil, fmt.Errorf("unsupported encoding %v", t.Encoding)
		}

	case *btf.Union:
		needUtils = true
		return getCastValue(t.Name, t.Size, v, typesPkg)

	case *btf.Struct:
		needUtils = true
		return getCastValue(t.Name, t.Size, v, typesPkg)

	default:
		return "", fmt.Errorf("unsupported type %T", t)
	}
}

func getValue[T comparable](v *ebpf.VariableSpec) (out T, err error) {
	if err := v.Get(&out); err != nil {
		return out, fmt.Errorf("getting value: %w", err)
	}
	return out, nil
}

// getCastValue gets the default value of a variable and returns a string of Go
// code that casts the value to the appropriate Go type using the cast() helper
// provided by util_generated.go.
//
//	cast[uint32]([]byte{0x01, 0x00, 0x00, 0x00}
func getCastValue(name string, size uint32, v *ebpf.VariableSpec, typesPkg string) (string, error) {
	b := make([]byte, size)
	if err := v.Get(b); err != nil {
		return "", fmt.Errorf("getting value: %w", err)
	}
	return fmt.Sprintf("cast[%s](%#v)", qualifiedTypeName(name, typesPkg), b), nil
}

// tagsToComment converts a slice of tags into a tab-indented string with
// each line prefixed with "//". The first letter of each tag is capitalized
// and a period is added at the end if it doesn't already have one.
func tagsToComment(tags []string) (string, error) {
	var b strings.Builder

	for i, tag := range tags {
		if tag == "" {
			return "", fmt.Errorf("empty tag")
		}

		tag = sentencify(tag)

		// Separate tags by newline comments.
		if i != 0 {
			b.WriteString("\t//\n")
		}

		// Wrap all tags to 80 chars and prefix all lines with //.
		b.WriteString(wrapString(tag, "\t// "))
	}

	return b.String(), nil
}

func wrapString(in, prefix string) string {
	var b strings.Builder
	width := uint(80 - len(prefix))
	for line := range strings.SplitSeq(wordwrap.WrapString(in, width), "\n") {
		// Trim trailing whitespace to allow for empty lines within comments.
		b.WriteString(strings.TrimSuffix(prefix+line, " "))
		b.WriteString("\n")
	}
	return b.String()
}

// sentencify capitalizes the first letter of a string and adds a period at
// the end if it doesn't already have one.
func sentencify(s string) string {
	if s == "" {
		return ""
	}

	s = strings.ToUpper(s[:1]) + s[1:]
	if s[len(s)-1] != '.' {
		return s + "."
	}

	return s
}

// qualifiedTypeName returns the qualified Go type name for a given C type name
// and Go package. If the package is empty, it returns the C type name as-is.
func qualifiedTypeName(name, typesPkg string) string {
	if typesPkg == "" {
		return name
	}

	_, pkg := path.Split(typesPkg)
	return fmt.Sprintf("%s.%s", pkg, camelCase(name))
}

// btfVarGoTypeName converts the value type of a btf.Var to its equivalent Go
// type name.
func btfVarGoTypeName(v *btf.Var, typesPkg string) (string, error) {
	switch t := btf.UnderlyingType(v.Type).(type) {
	case *btf.Int:
		if t.Encoding == btf.Char {
			return "byte", nil
		}

		if t.Encoding == btf.Bool {
			return "bool", nil
		}

		if t.Size > 8 {
			return "", fmt.Errorf("unsupported size %d", t.Size)
		}

		base := "int"
		if t.Encoding == btf.Unsigned {
			base = "uint"
		}
		return fmt.Sprintf("%s%d", base, t.Size*8), nil

	case *btf.Union:
		// Reference a union-equivalent type to be rendered with `dpgen type`.
		needExternalTypes = true
		return qualifiedTypeName(t.Name, typesPkg), nil

	case *btf.Struct:
		// Reference a struct-equivalent type to be rendered with `dpgen type`.
		needExternalTypes = true
		return qualifiedTypeName(t.Name, typesPkg), nil

	default:
		return "", fmt.Errorf("unsupported type %T", btf.UnderlyingType(v.Type))
	}
}

// goValueLiteral returns a string representation of a Go value.
func goValueLiteral(v any) string {
	switch t := v.(type) {
	case []byte:
		// Replace a slice literal with a fixed-size array literal. Since we can't
		// create arrays of a given size at runtime to feed to fmt.Sprintf(), do a
		// manual conversion.
		return strings.Replace(fmt.Sprintf("%#v", t), "[]byte{", fmt.Sprintf("[%d]byte{", len(t)), 1)
	case string:
		// String means a struct or union initializer, typically of the format
		// `cast[GoType](byteSlice)`. Emit these into the struct literal as-is since
		// the string represents valid Go code.
		return t
	}

	return fmt.Sprintf("%#v", v)
}

// join joins a slice of strings into a comma-separated string, wrapping lines
// and indenting with two tabs.
func join(vars []string) string {
	// Chosen to roughly fit "return &BPFFoo{" and some defaults on the first line.
	const maxLen = 60

	var out bytes.Buffer
	var line bytes.Buffer

	for i, s := range vars {
		line.WriteString(s)
		if i == len(vars)-1 {
			// Last entry, no further output.
			break
		}

		// Not the last entry, write a comma.
		line.WriteString(",")

		if line.Len() > maxLen || len(vars[i+1]) > maxLen {
			// If the current line or the next entry are too long, flush the line and
			// write a newline.
			out.Write(line.Bytes())
			line.Reset()

			line.WriteString("\n\t\t")
		} else {
			// Otherwise, separate entries with a space.
			line.WriteString(" ")
		}
	}

	out.Write(line.Bytes())

	return out.String()
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/mitchellh/go-wordwrap"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/datapath/config"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	protobufTagName = "protobuf"
)

func runConfig(cmd *cobra.Command, args []string) error {
	spec, err := ebpf.LoadCollectionSpec(inPath)
	if err != nil {
		return fmt.Errorf("loading spec: %w", err)
	}

	fields, err := specToFields(spec, kind)
	if err != nil {
		return fmt.Errorf("generating fields: %w", err)
	}

	s, err := fieldsToStruct(fields, name, embeds)
	if err != nil {
		return fmt.Errorf("generating config struct: %w", err)
	}

	var b strings.Builder
	if err := writeCopyrightHeader(&b); err != nil {
		return fmt.Errorf("writing copyright header: %w", err)
	}

	b.WriteString("package latest\n\n")
	b.WriteString("import \"fmt\"\n\n")
	b.WriteString(s)
	os.WriteFile(goOut, []byte(b.String()), 0644)

	b.Reset()
	s, err = fieldsToMessage(fields, name, embeds)
	if err != nil {
		return fmt.Errorf("generating config struct: %w", err)
	}
	if err := writeCopyrightHeader(&b); err != nil {
		return fmt.Errorf("writing copyright header: %w", err)
	}
	if err := writeProtoHeader(&b, goPkg, protoImports); err != nil {
		return fmt.Errorf("writing proto header: %w", err)
	}
	b.WriteString(s)
	fmt.Println(protoOut)
	os.WriteFile(protoOut, []byte(b.String()), 0644)

	return nil
}

type field struct {
	comment   string
	goName    string
	cName     string
	protoType string
	defValue  string
	size      int
}

func specToFields(spec *ebpf.CollectionSpec, kind string) ([]field, error) {
	kind = "kind:" + kind
	fields := make([]field, 0, len(spec.Variables))

	for n, v := range spec.Variables {
		// Only consider variables in a specific config section to avoid interfering
		// with unrelated objects.
		if v.SectionName != config.Section {
			continue
		}

		// DECLARE_CONFIG prefixes the variable name with a well-known prefix to
		// avoid collisions with other variables with common names.
		n = strings.TrimPrefix(n, config.ConstantPrefix)

		if v.Type == nil {
			return nil, fmt.Errorf("variable %s has no type information, was the ELF built without BTF?", n)
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
			return nil, fmt.Errorf("variable %s has no doc comment", n)
		}

		protoType, size, err := btfVarProtoType(v.Type)
		if err != nil {
			return nil, fmt.Errorf("variable %s: getting Go type: %w", n, err)
		}

		comment, err := tagsToComment(tags)
		if err != nil {
			return nil, fmt.Errorf("variable %s: converting tags to comments: %w", n, err)
		}

		defValue, err := varGoValue(v)
		if err != nil {
			return nil, fmt.Errorf("variable %s: getting default Go value: %w", n, err)
		}

		fields = append(fields, field{
			comment:   comment,
			goName:    camelCase(n),
			cName:     n,
			protoType: protoType,
			defValue:  goValueLiteral(defValue),
			size:      size,
		})
	}

	slices.SortStableFunc(fields, func(a, b field) int {
		return strings.Compare(a.goName, b.goName)
	})

	return fields, nil
}

// fieldsToStruct generates a Go struct from the fields derived from variables
// in the CollectionSpec.
func fieldsToStruct(fields []field, name string, embeds []string) (string, error) {
	var b strings.Builder

	// Render a constructor with default values set using ASSIGN_CONFIG.
	var params []string
	for _, e := range embeds {
		params = append(params, fmt.Sprintf("%s *%s", strings.ToLower(e), e))
	}

	b.WriteString(fmt.Sprintf("func New%s(%s) *%s {\n", name, strings.Join(params, ", "), name))
	b.WriteString(fmt.Sprintf("\tr := &%s{}\n", name))
	for _, f := range fields {
		b.WriteString(fmt.Sprintf("\tr.%s = %s\n", f.goName, f.defValue))
	}
	for _, e := range embeds {
		b.WriteString(fmt.Sprintf("\tr.%s = %s\n", e, strings.ToLower(e)))
	}
	b.WriteString("\treturn r\n")
	b.WriteString("}\n")

	b.WriteString(fmt.Sprintf("var fieldSizes%s = map[string]int{\n", name))
	for _, field := range fields {
		b.WriteString(fmt.Sprintf("\t\"%s\": %d,\n", field.cName, field.size))
	}
	b.WriteString("}\n")

	b.WriteString(fmt.Sprintf("\nfunc (c *%s) SizeOf(fieldName string) int {\n", name))
	for _, e := range embeds {
		b.WriteString(fmt.Sprintf("\tif c.%s.SizeOf(fieldName) != 0 {\n", e))
		b.WriteString(fmt.Sprintf("\t\treturn c.%s.SizeOf(fieldName)\n", e))
		b.WriteString("\t}\n")
	}
	b.WriteString(fmt.Sprintf("\treturn fieldSizes%s[fieldName]\n", name))
	b.WriteString("}\n")

	b.WriteString(fmt.Sprintf("\nfunc (c *%s) Map() (map[string]any, error) {\n", name))
	b.WriteString("\tresult := make(map[string]any)\n")
	for _, e := range embeds {
		b.WriteString(fmt.Sprintf("\tmap%s, err := c.%s.Map()\n", e, e))

		b.WriteString("\tif err != nil {\n")
		b.WriteString(fmt.Sprintf("\t\treturn nil, fmt.Errorf(\"%s: %%w\", err)\n", e))
		b.WriteString("\t}\n")

		b.WriteString(fmt.Sprintf("\tfor name, val := range map%s {\n", e))
		b.WriteString("\t\tif _, ok := result[name]; ok {\n")
		b.WriteString(fmt.Sprintf("\t\t\treturn nil, fmt.Errorf(\"%s: %%s exists in two embedded types\", name)\n", e))
		b.WriteString("\t\t}\n")
		b.WriteString("\t\tresult[name] = val\n")
		b.WriteString("\t}\n")
	}
	for _, f := range fields {
		if f.protoType == "bytes" {
			// Make sure length is == specified size
			b.WriteString(fmt.Sprintf("\tif (len(c.%s) != %d) {\n", f.goName, f.size))
			b.WriteString(fmt.Sprintf("\t\treturn nil, fmt.Errorf(\"%s must be %d bytes (got %%d)\", len(c.%s))\n", f.goName, f.size, f.goName))
			b.WriteString("\t}\n")
			b.WriteString(fmt.Sprintf("\tresult[\"%s\"] = c.%s\n", f.cName, f.goName))
		} else if f.size <= 2 && f.protoType != "bool" {
			var base string
			if strings.HasPrefix(f.protoType, "uint") {
				base = "uint"
			} else if strings.HasPrefix(f.protoType, "int") {
				base = "int"
			}
			nativeType := fmt.Sprintf("%s%d", base, f.size*8)
			// Make sure value fits into f.lenBytes
			b.WriteString(fmt.Sprintf("\t%s := %s(c.%s)\n", f.goName, nativeType, f.goName))
			b.WriteString(fmt.Sprintf("\tif (%s(%s) != c.%s) {\n", f.protoType, f.goName, f.goName))
			b.WriteString(fmt.Sprintf("\t\treturn nil, fmt.Errorf(\"%s must fit into a %s (value = %%d)\", c.%s)\n", f.goName, nativeType, f.goName))
			b.WriteString("\t}\n")
			b.WriteString(fmt.Sprintf("\tresult[\"%s\"] = %s\n", f.cName, f.goName))
		} else {
			b.WriteString(fmt.Sprintf("\tresult[\"%s\"] = c.%s\n", f.cName, f.goName))
		}
	}
	b.WriteString("\treturn result, nil\n")
	b.WriteString("}\n")

	return b.String(), nil
}

// fieldsToMessage generates a protobuf IDL message from the fields derived from variables
// in the CollectionSpec.
func fieldsToMessage(fields []field, name string, embeds []string) (string, error) {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("message %s {\n", name))

	n := 1
	for _, f := range fields {
		b.WriteString(f.comment)
		b.WriteString(fmt.Sprintf("\t%s %s = %d;\n", f.protoType, f.cName, n))
		n++
	}

	if len(embeds) > 0 {
		if len(fields) > 0 {
			b.WriteString("\n")
		}
		for _, e := range embeds {
			b.WriteString(fmt.Sprintf("\t%s %s = %d;\n", e, strings.ToLower(e), n))
		}
	}
	b.WriteString("}\n")

	return b.String(), nil
}

// varGoValue returns the Go value of a variable as an any.
func varGoValue(v *ebpf.VariableSpec) (any, error) {
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
		s := make([]byte, t.Size)
		if err := v.Get(&s); err != nil {
			return nil, fmt.Errorf("getting value: %w", err)
		}
		return s, nil

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

// camelCase converts a string like "foo_bar" to "FooBar".
func camelCase(s string) string {
	var b strings.Builder
	for w := range strings.SplitSeq(s, "_") {
		// protoc-gen-go handles names like "nat_46x64_prefix"
		// by inserting a _ before the numeric part:
		// Nat_46X64Prefix. Special case this to ensure the name
		// matches what will be generated.
		if w[0] >= '0' && w[0] <= '9' {
			w = "_" + w
		}
		b.WriteString(cases.Title(language.English, cases.NoLower).String(w))
	}
	return b.String()
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
		b.WriteString(prefix)
		b.WriteString(line)
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

// btfVarGoType converts the type of an integer btf.Var to its equivalent Go
// and protobuf type name.
func btfVarProtoType(v *btf.Var) (string, int, error) {
	switch t := btf.UnderlyingType(v.Type).(type) {
	case *btf.Int:
		if t.Encoding == btf.Char {
			return "int32", int(t.Size), nil
		}

		if t.Encoding == btf.Bool {
			return "bool", int(t.Size), nil
		}

		if t.Size > 8 {
			return "", 0, fmt.Errorf("unsupported size %d", t.Size)
		}

		base := "int"
		if t.Encoding == btf.Unsigned {
			base = "uint"
		}
		var protoType string
		if t.Size <= 2 {
			protoType = fmt.Sprintf("%s32", base)
		} else {
			protoType = fmt.Sprintf("%s%d", base, t.Size*8)
		}
		return protoType, int(t.Size), nil

	case *btf.Union:
		// Unions can't be represented in Go and are most often used for accessing
		// subfields of addresses. Emit a fixed-size byte array instead.
		return "bytes", int(t.Size), nil

	default:
		return "", 0, fmt.Errorf("unsupported type %T", btf.UnderlyingType(v.Type))
	}
}

// goValueLiteral returns a string representation of a Go value.
func goValueLiteral(v any) string {
	str := fmt.Sprintf("%#v", v)
	switch v.(type) {
	case []byte:
		// Replace a slice literal with a fixed-size array literal. Since we can't
		// create arrays of a given size at runtime to feed to fmt.Sprintf(), do a
		// manual conversion.
		str = strings.Replace(str, "[]byte{", "[]byte{", 1)
	}
	return str
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

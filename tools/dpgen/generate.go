// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/mitchellh/go-wordwrap"

	"github.com/cilium/cilium/pkg/datapath/config"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Common acronyms to transform into stylized form for Go field names.
var stylized = map[string]string{
	"bpf":     "BPF",
	"lxc":     "LXC",
	"xdp":     "XDP",
	"ipv4":    "IPv4",
	"ipv6":    "IPv6",
	"nat":     "NAT",
	"mac":     "MAC",
	"mtu":     "MTU",
	"id":      "ID",
	"ip":      "IP",
	"netns":   "NetNS",
	"ipcache": "IPCache",
}

// varsToStruct generates a Go struct from the configuration variables in the
// CollectionSpec.
func varsToStruct(spec *ebpf.CollectionSpec, name, kind, comment string, embeds []string) (string, error) {
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
		if v.MapName() != config.Section {
			continue
		}

		// DECLARE_CONFIG prefixes the variable name with a well-known prefix to
		// avoid collisions with other variables with common names.
		n = strings.TrimPrefix(n, config.ConstantPrefix)

		if v.Type() == nil {
			return "", fmt.Errorf("variable %s has no type information, was the ELF built without BTF?", n)
		}

		// Skip variables that don't have the requested kind.
		tags := v.Type().Tags
		if !slices.Contains(tags, kind) {
			continue
		}

		// Pop the kind tag from the list of tags, we don't want to render it out
		// to the config struct.
		tags = slices.DeleteFunc(tags, func(s string) bool { return s == kind })

		if len(tags) == 0 || tags[0] == "" {
			return "", fmt.Errorf("variable %s has no doc comment", n)
		}

		typ, err := btfVarGoType(v.Type())
		if err != nil {
			return "", fmt.Errorf("variable %s: getting Go type: %w", n, err)
		}

		comment, err := tagsToComment(tags)
		if err != nil {
			return "", fmt.Errorf("variable %s: converting tags to comments: %w", n, err)
		}

		defValue, err := varGoValue(v)
		if err != nil {
			return "", fmt.Errorf("variable %s: getting default Go value: %w", n, err)
		}

		fields = append(fields, field{comment, camelCase(n), n, typ, fmt.Sprintf("%#v", defValue)})
	}

	slices.SortStableFunc(fields, func(a, b field) int {
		return strings.Compare(a.goName, b.goName)
	})

	var b strings.Builder

	// Render a Go type definition for a configuration struct.
	if comment != "" {
		b.WriteString(wrapString(comment, "// "))
	}
	b.WriteString(fmt.Sprintf("type %s struct {\n", name))
	if kind == "kind:object" {
		b.WriteString(fmt.Sprintf("\tBPFNode\n"))
	}

	for _, f := range fields {
		b.WriteString(f.comment)
		b.WriteString(fmt.Sprintf("\t%s %s `%s:\"%s\"`\n", f.goName, f.typ, config.TagName, f.cName))
	}

	if len(embeds) > 0 {
		b.WriteString("\n")
		for _, e := range embeds {
			b.WriteString(fmt.Sprintf("\t%s\n", e))
		}
	}
	b.WriteString("}\n")

	// Render a constructor with default values set using ASSIGN_CONFIG.
	b.WriteString(fmt.Sprintf("\nfunc New%s() *%s {\n", name, name))
	b.WriteString(fmt.Sprintf("\treturn &%s{", name))
	var vals []string
	if kind == "kind:object" {
		vals = append(vals, "*NewBPFNode()")
	}
	for _, f := range fields {
		vals = append(vals, f.defValue)
	}
	b.WriteString(strings.Join(vals, ", "))
	b.WriteString("}\n")
	b.WriteString("}\n")

	return b.String(), nil
}

// varGoValue returns the Go value of a variable as an any.
func varGoValue(v *ebpf.VariableSpec) (any, error) {
	switch t := btf.UnderlyingType(v.Type().Type).(type) {
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

// camelCase converts a string like "foo_bar" to "FooBar". It capitalizes the
// acronyms defined in 'stylized'.
func camelCase(s string) string {
	var b strings.Builder
	words := strings.Split(s, "_")
	for _, w := range words {
		w = stylize(strings.ToLower(w))
		b.WriteString(cases.Title(language.English, cases.NoLower).String(w))
	}
	return b.String()
}

func stylize(s string) string {
	if v, ok := stylized[s]; ok {
		return v
	}
	return s
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
	lines := strings.Split(wordwrap.WrapString(in, width), "\n")
	for _, line := range lines {
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
// type name.
func btfVarGoType(v *btf.Var) (string, error) {
	i, ok := btf.As[*btf.Int](v.Type)
	if !ok {
		return "", fmt.Errorf("unsupported type %T", v.Type)
	}

	if i.Encoding == btf.Char {
		return "byte", nil
	}

	if i.Encoding == btf.Bool {
		return "bool", nil
	}

	if i.Size > 8 {
		return "", fmt.Errorf("unsupported size %d", i.Size)
	}

	base := "int"
	if i.Encoding == btf.Unsigned {
		base = "uint"
	}
	return fmt.Sprintf("%s%d", base, i.Size*8), nil
}

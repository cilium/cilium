//go:build !windows

package gen

import (
	"bytes"
	_ "embed"
	"fmt"
	"go/build/constraint"
	"go/token"
	"io"
	"sort"
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"

	"github.com/cilium/ebpf/btf"
	b2gInt "github.com/cilium/ebpf/cmd/bpf2go/internal"
	"github.com/cilium/ebpf/internal"
)

//go:embed output.tpl
var commonRaw string

var commonTemplate = template.Must(template.New("common").Parse(commonRaw))

type templateName string

func (n templateName) maybeExport(str string) string {
	if token.IsExported(string(n)) {
		return toUpperFirst(str)
	}

	return str
}

func (n templateName) Bytes() string {
	return "_" + toUpperFirst(string(n)) + "Bytes"
}

func (n templateName) Specs() string {
	return string(n) + "Specs"
}

func (n templateName) ProgramSpecs() string {
	return string(n) + "ProgramSpecs"
}

func (n templateName) MapSpecs() string {
	return string(n) + "MapSpecs"
}

func (n templateName) VariableSpecs() string {
	return string(n) + "VariableSpecs"
}

func (n templateName) Load() string {
	return n.maybeExport("load" + toUpperFirst(string(n)))
}

func (n templateName) LoadObjects() string {
	return n.maybeExport("load" + toUpperFirst(string(n)) + "Objects")
}

func (n templateName) Objects() string {
	return string(n) + "Objects"
}

func (n templateName) Maps() string {
	return string(n) + "Maps"
}

func (n templateName) Variables() string {
	return string(n) + "Variables"
}

func (n templateName) Programs() string {
	return string(n) + "Programs"
}

func (n templateName) CloseHelper() string {
	return "_" + toUpperFirst(string(n)) + "Close"
}

type GenerateArgs struct {
	// Package of the resulting file.
	Package string
	// The prefix of all names declared at the top-level.
	Stem string
	// Build Constraints included in the resulting file.
	Constraints constraint.Expr
	// Maps to be emitted.
	Maps []string
	// Variables to be emitted.
	Variables []string
	// Programs to be emitted.
	Programs []string
	// Types to be emitted.
	Types []btf.Type
	// Filename of the object to embed.
	ObjectFile string
	// Output to write template to.
	Output io.Writer
	// Function which transforms the input into a valid go identifier. Uses the default behaviour if nil
	Identifier func(string) string
}

// Generate bindings for a BPF ELF file.
func Generate(args GenerateArgs) error {
	if args.Identifier == nil {
		args.Identifier = internal.Identifier
	}
	if !token.IsIdentifier(args.Stem) {
		return fmt.Errorf("%q is not a valid identifier", args.Stem)
	}

	if strings.ContainsAny(args.ObjectFile, "\n") {
		// Prevent injecting newlines into the template.
		return fmt.Errorf("file %q contains an invalid character", args.ObjectFile)
	}

	for _, typ := range args.Types {
		if _, ok := btf.As[*btf.Datasec](typ); ok {
			// Avoid emitting .rodata, .bss, etc. for now. We might want to
			// name these types differently, etc.
			return fmt.Errorf("can't output btf.Datasec: %s", typ)
		}
	}

	maps := make(map[string]string)
	for _, name := range args.Maps {
		maps[name] = args.Identifier(name)
	}

	variables := make(map[string]string)
	for _, name := range args.Variables {
		variables[name] = args.Identifier(name)
	}

	programs := make(map[string]string)
	for _, name := range args.Programs {
		programs[name] = args.Identifier(name)
	}

	typeNames := make(map[btf.Type]string)
	for _, typ := range args.Types {
		// NB: This also deduplicates types.
		typeNames[typ] = args.Stem + args.Identifier(typ.TypeName())
	}

	// Ensure we don't have conflicting names and generate a sorted list of
	// named types so that the output is stable.
	types, err := sortTypes(typeNames)
	if err != nil {
		return err
	}

	gf := &btf.GoFormatter{
		Names:      typeNames,
		Identifier: args.Identifier,
	}

	var typeDecls []string
	needsStructsPkg := false
	for _, typ := range types {
		name := typeNames[typ]
		decl, err := gf.TypeDeclaration(name, typ)
		if err != nil {
			return fmt.Errorf("generating %s: %w", name, err)
		}
		_, ok := btf.As[*btf.Struct](typ)
		needsStructsPkg = needsStructsPkg || ok
		typeDecls = append(typeDecls, decl)
	}

	ctx := struct {
		Module           string
		Package          string
		Constraints      constraint.Expr
		Name             templateName
		Maps             map[string]string
		Variables        map[string]string
		Programs         map[string]string
		TypeDeclarations []string
		File             string
		NeedsStructsPkg  bool
	}{
		b2gInt.CurrentModule,
		args.Package,
		args.Constraints,
		templateName(args.Stem),
		maps,
		variables,
		programs,
		typeDecls,
		args.ObjectFile,
		needsStructsPkg,
	}

	var buf bytes.Buffer
	if err := commonTemplate.Execute(&buf, &ctx); err != nil {
		return fmt.Errorf("can't generate types: %s", err)
	}

	return internal.WriteFormatted(buf.Bytes(), args.Output)
}

// sortTypes returns a list of types sorted by their (generated) Go type name.
//
// Duplicate Go type names are rejected.
func sortTypes(typeNames map[btf.Type]string) ([]btf.Type, error) {
	var types []btf.Type
	var names []string
	for typ, name := range typeNames {
		i := sort.SearchStrings(names, name)
		if i >= len(names) {
			types = append(types, typ)
			names = append(names, name)
			continue
		}

		if names[i] == name {
			return nil, fmt.Errorf("type name %q is used multiple times", name)
		}

		types = append(types[:i], append([]btf.Type{typ}, types[i:]...)...)
		names = append(names[:i], append([]string{name}, names[i:]...)...)
	}

	return types, nil
}

func toUpperFirst(str string) string {
	first, n := utf8.DecodeRuneInString(str)
	return string(unicode.ToUpper(first)) + str[n:]
}

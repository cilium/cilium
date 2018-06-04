package pgs

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"path/filepath"

	"github.com/golang/protobuf/protoc-gen-go/generator"
)

var protectedNames = map[Name]Name{
	"Reset":               "Reset_",
	"String":              "String_",
	"ProtoMessage":        "ProtoMessage_",
	"Marshal":             "Marshal_",
	"Unmarshal":           "Unmarshal_",
	"ExtensionRangeArray": "ExtensionRangeArray_",
	"ExtensionMap":        "ExtensionMap_",
	"Descriptor":          "Descriptor_",
}

// A Name describes a symbol (Message, Field, Enum, Service, Field) of the
// Entity. It can be converted to multiple forms using the provided helper
// methods, or a custom transform can be used to modify its behavior.
type Name string

// String satisfies the strings.Stringer interface.
func (n Name) String() string { return string(n) }

// UpperCamelCase converts Name n to upper camelcase, where each part is
// title-cased and concatenated with no separator.
func (n Name) UpperCamelCase() Name { return n.Transform(strings.Title, strings.Title, "") }

// PGGUpperCamelCase converts Name n to the protoc-gen-go defined upper
// camelcase. The rules are slightly different from UpperCamelCase in that
// leading underscores are converted to 'X', mid-string underscores followed by
// lowercase letters are removed and the letter is capitalized, all other
// punctuation is preserved. This method should be used when deriving names of
// protoc-gen-go generated code (ie, message/service struct names and field
// names). In addition, this method ensures the Name does not conflict with one
// of the generated method names, appending the fields with an underscore in
// the same manner as protoc-gen-go.
//
// See: https://godoc.org/github.com/golang/protobuf/protoc-gen-go/generator#CamelCase
func (n Name) PGGUpperCamelCase() Name {
	out := Name(generator.CamelCase(n.String()))

	if use, protected := protectedNames[out]; protected {
		return use
	}

	return out
}

// LowerCamelCase converts Name n to lower camelcase, where each part is
// title-cased and concatenated with no separator except the first which is
// lower-cased.
func (n Name) LowerCamelCase() Name { return n.Transform(strings.Title, strings.ToLower, "") }

// ScreamingSnakeCase converts Name n to screaming-snake-case, where each part
// is all-caps and concatenated with underscores.
func (n Name) ScreamingSnakeCase() Name { return n.Transform(strings.ToUpper, strings.ToUpper, "_") }

// LowerSnakeCase converts Name n to lower-snake-case, where each part is
// lower-cased and concatenated with underscores.
func (n Name) LowerSnakeCase() Name { return n.Transform(strings.ToLower, strings.ToLower, "_") }

// UpperSnakeCase converts Name n to upper-snake-case, where each part is
// title-cased and concatenated with underscores.
func (n Name) UpperSnakeCase() Name { return n.Transform(strings.Title, strings.Title, "_") }

// LowerDotNotation converts Name n to lower dot notation, where each part is
// lower-cased and concatenated with periods.
func (n Name) LowerDotNotation() Name { return n.Transform(strings.ToLower, strings.ToLower, ".") }

// UpperDotNotation converts Name n to upper dot notation, where each part is
// title-cased and concatenated with periods.
func (n Name) UpperDotNotation() Name { return n.Transform(strings.Title, strings.Title, ".") }

// Split breaks apart Name n into its constituent components. Precedence
// follows dot notation, then underscores (excluding underscore prefixes), then
// camelcase. Numbers are treated as standalone components.
func (n Name) Split() (parts []string) {
	ns := string(n)

	switch {
	case ns == "":
		return []string{""}
	case strings.LastIndex(ns, ".") >= 0:
		return strings.Split(ns, ".")
	case strings.LastIndex(ns, "_") > 0: // leading underscore does not count
		parts = strings.Split(ns, "_")
		if parts[0] == "" {
			parts[1] = "_" + parts[1]
			return parts[1:]
		}
		return
	default: // camelCase
		buf := &bytes.Buffer{}
		var capt, lodash, num bool
		for _, r := range ns {
			uc := unicode.IsUpper(r) || unicode.IsTitle(r)
			dg := unicode.IsDigit(r)

			if r == '_' && buf.Len() == 0 && len(parts) == 0 {
				lodash = true
			}

			if uc && !capt && buf.Len() > 0 && !lodash { // new upper letter
				parts = append(parts, buf.String())
				buf.Reset()
			} else if dg && !num && buf.Len() > 0 && !lodash { // new digit
				parts = append(parts, buf.String())
				buf.Reset()
			} else if !uc && capt && buf.Len() > 1 { // upper to lower
				if ss := buf.String(); len(ss) > 1 &&
					(len(ss) != 2 || ss[0] != '_') {
					pr, _ := utf8.DecodeLastRuneInString(ss)
					parts = append(parts, strings.TrimSuffix(ss, string(pr)))
					buf.Reset()
					buf.WriteRune(pr)
				}
			} else if !dg && num && buf.Len() >= 1 {
				parts = append(parts, buf.String())
				buf.Reset()
			}

			num = dg
			capt = uc
			buf.WriteRune(r)
		}
		parts = append(parts, buf.String())
		return
	}
}

// NameTransformer is a function that mutates a string. Many of the methods in
// the standard strings package satisfy this signature.
type NameTransformer func(string) string

// Chain combines the behavior of two Transformers into one. If multiple
// transformations need to be performed on a Name, this method should be used
// to reduce it to a single transformation before applying.
func (n NameTransformer) Chain(t NameTransformer) NameTransformer {
	return func(s string) string { return t(n(s)) }
}

// Transform applies a transformation to the parts of Name n, returning a new
// Name. Transformer first is applied to the first part, with mod applied to
// all subsequent ones. The parts are then concatenated with the separator sep.
// For optimal efficiency, multiple NameTransformers should be Chained together
// before calling Transform.
func (n Name) Transform(mod, first NameTransformer, sep string) Name {
	parts := n.Split()

	for i, p := range parts {
		if i == 0 {
			parts[i] = first(p)
		} else {
			parts[i] = mod(p)
		}
	}

	return Name(strings.Join(parts, sep))
}

// A TypeName describes the name of a type (type on a field, or method signature)
type TypeName string

// String satisfies the strings.Stringer interface.
func (n TypeName) String() string { return string(n) }

// Element returns the TypeName of the element of n. For types other than
// slices and maps, this just returns n.
func (n TypeName) Element() TypeName {
	parts := strings.SplitN(string(n), "]", 2)
	return TypeName(parts[len(parts)-1])
}

// Key returns the TypeName of the key of n. For slices, the return TypeName is
// always "int", and for non slice/map types an empty TypeName is returned.
func (n TypeName) Key() TypeName {
	parts := strings.SplitN(string(n), "]", 2)
	if len(parts) == 1 {
		return TypeName("")
	}

	parts = strings.SplitN(parts[0], "[", 2)
	if len(parts) != 2 {
		return TypeName("")
	} else if parts[1] == "" {
		return TypeName("int")
	}

	return TypeName(parts[1])
}

// Pointer converts TypeName n to it's pointer type. If n is already a pointer,
// slice, or map, it is returned unmodified.
func (n TypeName) Pointer() TypeName {
	ns := string(n)
	if strings.HasPrefix(ns, "*") ||
		strings.HasPrefix(ns, "[") ||
		strings.HasPrefix(ns, "map[") {
		return n
	}

	return TypeName("*" + ns)
}

// Value converts TypeName n to it's value type. If n is already a value type,
// slice, or map it is returned unmodified.
func (n TypeName) Value() TypeName {
	return TypeName(strings.TrimPrefix(string(n), "*"))
}

// A FilePath describes the name of a file or directory. This type simplifies
// path related operations.
type FilePath string

// JoinPaths is an convenient alias around filepath.Join, to easily create
// FilePath types.
func JoinPaths(elem ...string) FilePath { return FilePath(filepath.Join(elem...)) }

// String satisfies the strings.Stringer interface.
func (n FilePath) String() string { return string(n) }

// Dir returns the parent directory of the current FilePath. This method is an
// alias around filepath.Dir.
func (n FilePath) Dir() FilePath { return FilePath(filepath.Dir(n.String())) }

// Base returns the base of the current FilePath (the last element in the
// path). This method is an alias around filepath.Base.
func (n FilePath) Base() string { return filepath.Base(n.String()) }

// Ext returns the extension of the current FilePath (starting at and including
// the last '.' in the FilePath). This method is an alias around filepath.Ext.
func (n FilePath) Ext() string { return filepath.Ext(n.String()) }

// BaseName returns the Base of the current FilePath without Ext.
func (n FilePath) BaseName() string { return strings.TrimSuffix(n.Base(), n.Ext()) }

// SetExt returns a new FilePath with the extension replaced with ext.
func (n FilePath) SetExt(ext string) FilePath { return n.SetBase(n.BaseName() + ext) }

// SetBase returns a new FilePath with the base element replaced with base.
func (n FilePath) SetBase(base string) FilePath { return n.Dir().Push(base) }

// Pop returns a new FilePath with the last element removed
func (n FilePath) Pop() FilePath { return JoinPaths(n.String(), "..") }

// Push returns a new FilePath with elem added to the end
func (n FilePath) Push(elem string) FilePath { return JoinPaths(n.String(), elem) }

func fullyQualifiedName(p, e Entity) string {
	return fmt.Sprintf("%s.%s", p.FullyQualifiedName(), e.Name())
}

package pgsgo

import (
	"fmt"
	"strings"

	pgs "github.com/lyft/protoc-gen-star"
)

func (c context) Type(f pgs.Field) TypeName {
	ft := f.Type()

	var t TypeName
	switch {
	case ft.IsMap():
		key := scalarType(ft.Key().ProtoType())
		return TypeName(fmt.Sprintf("map[%s]%s", key, c.elType(ft)))
	case ft.IsRepeated():
		return TypeName(fmt.Sprintf("[]%s", c.elType(ft)))
	case ft.IsEmbed():
		return c.importableTypeName(f, ft.Embed()).Pointer()
	case ft.IsEnum():
		t = c.importableTypeName(f, ft.Enum())
	default:
		t = scalarType(ft.ProtoType())
	}

	if f.Syntax() == pgs.Proto2 {
		return t.Pointer()
	}

	return t
}

func (c context) importableTypeName(f pgs.Field, e pgs.Entity) TypeName {
	t := TypeName(c.Name(e))

	if c.ImportPath(e) == c.ImportPath(f) {
		return t
	}

	return TypeName(fmt.Sprintf("%s.%s", c.PackageName(e), t))
}

func (c context) elType(ft pgs.FieldType) TypeName {
	el := ft.Element()
	switch {
	case el.IsEnum():
		return c.importableTypeName(ft.Field(), el.Enum())
	case el.IsEmbed():
		return c.importableTypeName(ft.Field(), el.Embed()).Pointer()
	default:
		return scalarType(el.ProtoType())
	}
}

func scalarType(t pgs.ProtoType) TypeName {
	switch t {
	case pgs.DoubleT:
		return "float64"
	case pgs.FloatT:
		return "float32"
	case pgs.Int64T, pgs.SFixed64, pgs.SInt64:
		return "int64"
	case pgs.UInt64T, pgs.Fixed64T:
		return "uint64"
	case pgs.Int32T, pgs.SFixed32, pgs.SInt32:
		return "int32"
	case pgs.UInt32T, pgs.Fixed32T:
		return "uint32"
	case pgs.BoolT:
		return "bool"
	case pgs.StringT:
		return "string"
	case pgs.BytesT:
		return "[]byte"
	default:
		panic("unreachable: invalid scalar type")
	}
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

// IsPointer reports whether TypeName n is a pointer type, slice or a map.
func (n TypeName) IsPointer() bool {
	ns := string(n)
	return strings.HasPrefix(ns, "*") ||
		strings.HasPrefix(ns, "[") ||
		strings.HasPrefix(ns, "map[")
}

// Pointer converts TypeName n to it's pointer type. If n is already a pointer,
// slice, or map, it is returned unmodified.
func (n TypeName) Pointer() TypeName {
	if n.IsPointer() {
		return n
	}
	return TypeName("*" + string(n))
}

// Value converts TypeName n to it's value type. If n is already a value type,
// slice, or map it is returned unmodified.
func (n TypeName) Value() TypeName {
	return TypeName(strings.TrimPrefix(string(n), "*"))
}

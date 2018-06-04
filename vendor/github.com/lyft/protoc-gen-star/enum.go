package pgs

import (
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/golang/protobuf/protoc-gen-go/generator"
)

// Enum describes an enumeration type. Its parent can be either a Message or a
// File.
type Enum interface {
	Entity

	// TypeName returns the type of this enum as it would be created in Go.
	// This value will only differ from Name for nested enums.
	TypeName() TypeName

	// Descriptor returns the proto descriptor for this Enum
	Descriptor() *generator.EnumDescriptor

	// Parent resolves to either a Message or File that directly contains this
	// Enum.
	Parent() ParentEntity

	// Values returns each defined enumeration value.
	Values() []EnumValue

	addValue(v EnumValue)
	setParent(p ParentEntity)
}

type enum struct {
	rawDesc *descriptor.EnumDescriptorProto
	genDesc *generator.EnumDescriptor

	parent ParentEntity

	vals []EnumValue

	comments string
}

func (e *enum) Name() Name                            { return Name(e.rawDesc.GetName()) }
func (e *enum) FullyQualifiedName() string            { return fullyQualifiedName(e.parent, e) }
func (e *enum) Syntax() Syntax                        { return e.parent.Syntax() }
func (e *enum) Package() Package                      { return e.parent.Package() }
func (e *enum) File() File                            { return e.parent.File() }
func (e *enum) BuildTarget() bool                     { return e.parent.BuildTarget() }
func (e *enum) Comments() string                      { return e.comments }
func (e *enum) Descriptor() *generator.EnumDescriptor { return e.genDesc }
func (e *enum) Parent() ParentEntity                  { return e.parent }
func (e *enum) Imports() []Package                    { return nil }
func (e *enum) TypeName() TypeName                    { return TypeName(strings.Join(e.genDesc.TypeName(), "_")) }

func (e *enum) Values() []EnumValue {
	ev := make([]EnumValue, len(e.vals))
	copy(ev, e.vals)
	return ev
}

func (e *enum) Extension(desc *proto.ExtensionDesc, ext interface{}) (bool, error) {
	return extension(e.rawDesc.GetOptions(), desc, &ext)
}

func (e *enum) accept(v Visitor) (err error) {
	if v == nil {
		return nil
	}

	if v, err = v.VisitEnum(e); err != nil || v == nil {
		return
	}

	for _, ev := range e.vals {
		if err = ev.accept(v); err != nil {
			return
		}
	}

	return
}

func (e *enum) addValue(v EnumValue) {
	v.setEnum(e)
	e.vals = append(e.vals, v)
}

func (e *enum) setParent(p ParentEntity) { e.parent = p }

var _ Enum = (*enum)(nil)

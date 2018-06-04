package pgs

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
)

// An EnumValue describes a name-value pair for an entry in an enum.
type EnumValue interface {
	Entity

	// Descriptor returns the proto descriptor for this Enum Value
	Descriptor() *descriptor.EnumValueDescriptorProto

	// Enum returns the parent Enum for this value
	Enum() Enum

	// Value returns the numeric enum value associated with this type
	Value() int32

	setEnum(e Enum)
}

type enumVal struct {
	desc *descriptor.EnumValueDescriptorProto
	enum Enum

	comments string
}

func (ev *enumVal) Name() Name                                       { return Name(ev.desc.GetName()) }
func (ev *enumVal) FullyQualifiedName() string                       { return fullyQualifiedName(ev.enum, ev) }
func (ev *enumVal) Syntax() Syntax                                   { return ev.enum.Syntax() }
func (ev *enumVal) Package() Package                                 { return ev.enum.Package() }
func (ev *enumVal) File() File                                       { return ev.enum.File() }
func (ev *enumVal) BuildTarget() bool                                { return ev.enum.BuildTarget() }
func (ev *enumVal) Comments() string                                 { return ev.comments }
func (ev *enumVal) Descriptor() *descriptor.EnumValueDescriptorProto { return ev.desc }
func (ev *enumVal) Enum() Enum                                       { return ev.enum }
func (ev *enumVal) Value() int32                                     { return ev.desc.GetNumber() }
func (ev *enumVal) Imports() []Package                               { return nil }

func (ev *enumVal) Extension(desc *proto.ExtensionDesc, ext interface{}) (bool, error) {
	return extension(ev.desc.GetOptions(), desc, &ext)
}

func (ev *enumVal) accept(v Visitor) (err error) {
	if v == nil {
		return nil
	}

	_, err = v.VisitEnumValue(ev)

	return
}

func (ev *enumVal) setEnum(e Enum) { ev.enum = e }

var _ EnumValue = (*enumVal)(nil)

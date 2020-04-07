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
	fqn  string

	info SourceCodeInfo
}

func (ev *enumVal) Name() Name                                       { return Name(ev.desc.GetName()) }
func (ev *enumVal) FullyQualifiedName() string                       { return ev.fqn }
func (ev *enumVal) Syntax() Syntax                                   { return ev.enum.Syntax() }
func (ev *enumVal) Package() Package                                 { return ev.enum.Package() }
func (ev *enumVal) File() File                                       { return ev.enum.File() }
func (ev *enumVal) BuildTarget() bool                                { return ev.enum.BuildTarget() }
func (ev *enumVal) SourceCodeInfo() SourceCodeInfo                   { return ev.info }
func (ev *enumVal) Descriptor() *descriptor.EnumValueDescriptorProto { return ev.desc }
func (ev *enumVal) Enum() Enum                                       { return ev.enum }
func (ev *enumVal) Value() int32                                     { return ev.desc.GetNumber() }
func (ev *enumVal) Imports() []File                                  { return nil }

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

func (ev *enumVal) childAtPath(path []int32) Entity {
	if len(path) == 0 {
		return ev
	}
	return nil
}

func (ev *enumVal) addSourceCodeInfo(info SourceCodeInfo) { ev.info = info }

var _ EnumValue = (*enumVal)(nil)

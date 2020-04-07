package pgs

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
)

// A Field describes a member of a Message. A field may also be a member of a
// OneOf on the Message.
type Field interface {
	Entity

	// Descriptor returns the proto descriptor for this field
	Descriptor() *descriptor.FieldDescriptorProto

	// Message returns the Message containing this Field.
	Message() Message

	// InOneOf returns true if the field is in a OneOf of the parent Message.
	InOneOf() bool

	// OneOf returns the OneOf that this field is apart of. Nil is returned if
	// the field is not within a OneOf.
	OneOf() OneOf

	// Type returns the FieldType of this Field.
	Type() FieldType

	// Required returns whether or not the field is labeled as required. This
	// will only be true if the syntax is proto2.
	Required() bool

	setMessage(m Message)
	setOneOf(o OneOf)
	addType(t FieldType)
}

type field struct {
	desc  *descriptor.FieldDescriptorProto
	fqn   string
	msg   Message
	oneof OneOf
	typ   FieldType

	info SourceCodeInfo
}

func (f *field) Name() Name                                   { return Name(f.desc.GetName()) }
func (f *field) FullyQualifiedName() string                   { return f.fqn }
func (f *field) Syntax() Syntax                               { return f.msg.Syntax() }
func (f *field) Package() Package                             { return f.msg.Package() }
func (f *field) Imports() []File                              { return f.typ.Imports() }
func (f *field) File() File                                   { return f.msg.File() }
func (f *field) BuildTarget() bool                            { return f.msg.BuildTarget() }
func (f *field) SourceCodeInfo() SourceCodeInfo               { return f.info }
func (f *field) Descriptor() *descriptor.FieldDescriptorProto { return f.desc }
func (f *field) Message() Message                             { return f.msg }
func (f *field) InOneOf() bool                                { return f.oneof != nil }
func (f *field) OneOf() OneOf                                 { return f.oneof }
func (f *field) Type() FieldType                              { return f.typ }
func (f *field) setMessage(m Message)                         { f.msg = m }
func (f *field) setOneOf(o OneOf)                             { f.oneof = o }

func (f *field) Required() bool {
	return f.Syntax().SupportsRequiredPrefix() &&
		f.desc.GetLabel() == descriptor.FieldDescriptorProto_LABEL_REQUIRED
}

func (f *field) addType(t FieldType) {
	t.setField(f)
	f.typ = t
}

func (f *field) Extension(desc *proto.ExtensionDesc, ext interface{}) (ok bool, err error) {
	return extension(f.desc.GetOptions(), desc, &ext)
}

func (f *field) accept(v Visitor) (err error) {
	if v == nil {
		return
	}

	_, err = v.VisitField(f)
	return
}

func (f *field) childAtPath(path []int32) Entity {
	if len(path) == 0 {
		return f
	}
	return nil
}

func (f *field) addSourceCodeInfo(info SourceCodeInfo) { f.info = info }

var _ Field = (*field)(nil)

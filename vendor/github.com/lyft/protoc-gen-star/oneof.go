package pgs

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
)

// OneOf describes a OneOf block within a Message. OneOfs behave like C++
// unions, where only one of the contained fields will exist on the Message.
type OneOf interface {
	Entity

	// Descriptor returns the underlying proto descriptor for this OneOf
	Descriptor() *descriptor.OneofDescriptorProto

	// Message returns the parent message for this OneOf.
	Message() Message

	// Fields returns all fields contained within this OneOf.
	Fields() []Field

	setMessage(m Message)
	addField(f Field)
}

type oneof struct {
	desc *descriptor.OneofDescriptorProto
	msg  Message
	flds []Field
	fqn  string

	info SourceCodeInfo
}

func (o *oneof) accept(v Visitor) (err error) {
	if v == nil {
		return
	}

	_, err = v.VisitOneOf(o)
	return
}

func (o *oneof) Name() Name                                   { return Name(o.desc.GetName()) }
func (o *oneof) FullyQualifiedName() string                   { return o.fqn }
func (o *oneof) Syntax() Syntax                               { return o.msg.Syntax() }
func (o *oneof) Package() Package                             { return o.msg.Package() }
func (o *oneof) File() File                                   { return o.msg.File() }
func (o *oneof) BuildTarget() bool                            { return o.msg.BuildTarget() }
func (o *oneof) SourceCodeInfo() SourceCodeInfo               { return o.info }
func (o *oneof) Descriptor() *descriptor.OneofDescriptorProto { return o.desc }
func (o *oneof) Message() Message                             { return o.msg }
func (o *oneof) setMessage(m Message)                         { o.msg = m }

func (o *oneof) Imports() (i []File) {
	// Mapping for avoiding duplicate entries
	mp := make(map[string]File, len(o.flds))
	for _, f := range o.flds {
		for _, imp := range f.Imports() {
			mp[imp.File().Name().String()] = imp
		}
	}
	for _, f := range mp {
		i = append(i, f)
	}
	return
}

func (o *oneof) Extension(desc *proto.ExtensionDesc, ext interface{}) (ok bool, err error) {
	return extension(o.desc.GetOptions(), desc, &ext)
}

func (o *oneof) Fields() []Field {
	f := make([]Field, len(o.flds))
	copy(f, o.flds)
	return f
}

func (o *oneof) addField(f Field) {
	f.setOneOf(o)
	o.flds = append(o.flds, f)
}

func (o *oneof) childAtPath(path []int32) Entity {
	if len(path) == 0 {
		return o
	}
	return nil
}

func (o *oneof) addSourceCodeInfo(info SourceCodeInfo) { o.info = info }

var _ OneOf = (*oneof)(nil)

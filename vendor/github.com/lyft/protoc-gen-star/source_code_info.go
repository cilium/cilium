package pgs

import (
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
)

const (
	packagePath               int32 = 2  // FileDescriptorProto.Package
	messageTypePath           int32 = 4  // FileDescriptorProto.MessageType
	enumTypePath              int32 = 5  // FileDescriptorProto.EnumType
	servicePath               int32 = 6  // FileDescriptorProto.Service
	syntaxPath                int32 = 12 // FileDescriptorProto.Syntax
	messageTypeFieldPath      int32 = 2  // DescriptorProto.Field
	messageTypeNestedTypePath int32 = 3  // DescriptorProto.NestedType
	messageTypeEnumTypePath   int32 = 4  // DescriptorProto.EnumType
	messageTypeOneofDeclPath  int32 = 8  // DescriptorProto.OneofDecl
	enumTypeValuePath         int32 = 2  // EnumDescriptorProto.Value
	serviceTypeMethodPath     int32 = 2  // ServiceDescriptorProto.Method
)

// SourceCodeInfo represents data about an entity from the source. Currently
// this only contains information about comments protoc associates with
// entities.
//
// All comments have their // or /* */ stripped by protoc. See the
// SourceCodeInfo documentation for more details about how comments are
// associated with entities.
type SourceCodeInfo interface {
	// Location returns the SourceCodeInfo_Location from the file descriptor.
	Location() *descriptor.SourceCodeInfo_Location

	// LeadingComments returns any comment immediately preceding the entity,
	// without any whitespace between it and the comment.
	LeadingComments() string

	// LeadingDetachedComments returns each comment block or line above the
	// entity but separated by whitespace.
	LeadingDetachedComments() []string

	// TrailingComments returns any comment immediately following the entity,
	// without any whitespace between it and the comment. If the comment would be
	// a leading comment for another entity, it won't be considered a trailing
	// comment.
	TrailingComments() string
}

type sci struct {
	desc *descriptor.SourceCodeInfo_Location
}

func (info sci) Location() *descriptor.SourceCodeInfo_Location { return info.desc }
func (info sci) LeadingComments() string                       { return info.desc.GetLeadingComments() }
func (info sci) LeadingDetachedComments() []string             { return info.desc.GetLeadingDetachedComments() }
func (info sci) TrailingComments() string                      { return info.desc.GetTrailingComments() }

var _ SourceCodeInfo = sci{}

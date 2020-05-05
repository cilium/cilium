package pgs

import (
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
)

// Syntax describes the proto syntax used to encode the proto file
type Syntax string

const (
	// Proto2 syntax permits the use of "optional" and "required" prefixes on
	// fields. Most of the field types in the generated go structs are pointers.
	// See: https://developers.google.com/protocol-buffers/docs/proto
	Proto2 Syntax = ""

	// Proto3 syntax only allows for optional fields, but defaults to the zero
	// value of that particular type. Most of the field types in the generated go
	// structs are value types.
	// See: https://developers.google.com/protocol-buffers/docs/proto3
	Proto3 Syntax = "proto3"
)

// SupportsRequiredPrefix returns true if s supports "optional" and
// "required" identifiers on message fields. Only Proto2 syntax supports this
// feature.
func (s Syntax) SupportsRequiredPrefix() bool { return s == Proto2 }

// String returns a string representation of the syntax.
func (s Syntax) String() string {
	return string(s)
}

// ProtoLabel wraps the FieldDescriptorProto_Label enum for better readability.
// It is a 1-to-1 conversion.
type ProtoLabel descriptor.FieldDescriptorProto_Label

const (
	// Optional (in the context of Proto2 syntax) identifies that the field may
	// be unset in the proto message. In Proto3 syntax, all fields are considered
	// Optional and default to their zero value.
	Optional = ProtoLabel(descriptor.FieldDescriptorProto_LABEL_OPTIONAL)

	// Required (in the context of Proto2 syntax) identifies that the field must
	// be set in the proto message. In Proto3 syntax, no fields can be identified
	// as Required.
	Required = ProtoLabel(descriptor.FieldDescriptorProto_LABEL_REQUIRED)

	// Repeated identifies that the field either permits multiple entries
	// (repeated) or is a map (map<key,val>). Determining which requires further
	// evaluation of the descriptor and whether or not the embedded message is
	// identified as a MapEntry (see IsMap on FieldType).
	Repeated = ProtoLabel(descriptor.FieldDescriptorProto_LABEL_REPEATED)
)

// Proto returns the FieldDescriptorProto_Label for this ProtoLabel. This
// method is exclusively used to improve readability without having to switch
// the types.
func (pl ProtoLabel) Proto() descriptor.FieldDescriptorProto_Label {
	return descriptor.FieldDescriptorProto_Label(pl)
}

// ProtoPtr returns a pointer to the FieldDescriptorProto_Label for this
// ProtoLabel.
func (pl ProtoLabel) ProtoPtr() *descriptor.FieldDescriptorProto_Label {
	l := pl.Proto()
	return &l
}

// String returns a string representation of the proto label.
func (pl ProtoLabel) String() string {
	return pl.Proto().String()
}

// ProtoType wraps the FieldDescriptorProto_Type enum for better readability
// and utility methods. It is a 1-to-1 conversion.
type ProtoType descriptor.FieldDescriptorProto_Type

// 1-to-1 mapping of FieldDescriptorProto_Type enum to ProtoType. While all are
// listed here, group types are not supported by this library.
const (
	DoubleT  = ProtoType(descriptor.FieldDescriptorProto_TYPE_DOUBLE)
	FloatT   = ProtoType(descriptor.FieldDescriptorProto_TYPE_FLOAT)
	Int64T   = ProtoType(descriptor.FieldDescriptorProto_TYPE_INT64)
	UInt64T  = ProtoType(descriptor.FieldDescriptorProto_TYPE_UINT64)
	Int32T   = ProtoType(descriptor.FieldDescriptorProto_TYPE_INT32)
	Fixed64T = ProtoType(descriptor.FieldDescriptorProto_TYPE_FIXED64)
	Fixed32T = ProtoType(descriptor.FieldDescriptorProto_TYPE_FIXED32)
	BoolT    = ProtoType(descriptor.FieldDescriptorProto_TYPE_BOOL)
	StringT  = ProtoType(descriptor.FieldDescriptorProto_TYPE_STRING)
	GroupT   = ProtoType(descriptor.FieldDescriptorProto_TYPE_GROUP)
	MessageT = ProtoType(descriptor.FieldDescriptorProto_TYPE_MESSAGE)
	BytesT   = ProtoType(descriptor.FieldDescriptorProto_TYPE_BYTES)
	UInt32T  = ProtoType(descriptor.FieldDescriptorProto_TYPE_UINT32)
	EnumT    = ProtoType(descriptor.FieldDescriptorProto_TYPE_ENUM)
	SFixed32 = ProtoType(descriptor.FieldDescriptorProto_TYPE_SFIXED32)
	SFixed64 = ProtoType(descriptor.FieldDescriptorProto_TYPE_SFIXED64)
	SInt32   = ProtoType(descriptor.FieldDescriptorProto_TYPE_SINT32)
	SInt64   = ProtoType(descriptor.FieldDescriptorProto_TYPE_SINT64)
)

// IsInt returns true if pt maps to an integer-like type. While EnumT types in
// Go are aliases of uint32, to correctly accommodate other languages with
// non-numeric enums, IsInt returns false for EnumT.
func (pt ProtoType) IsInt() bool {
	switch pt {
	case Int64T, UInt64T, SFixed64, SInt64, Fixed64T,
		Int32T, UInt32T, SFixed32, SInt32, Fixed32T:
		return true
	}

	return false
}

// IsNumeric returns true if pt maps to a numeric type. While EnumT types in Go
// are aliases of uint32, to correctly accommodate other languages with non-numeric
// enums, IsNumeric returns false for EnumT.
func (pt ProtoType) IsNumeric() bool { return pt == DoubleT || pt == FloatT || pt.IsInt() }

// Proto returns the FieldDescriptorProto_Type for this ProtoType. This
// method is exclusively used to improve readability without having to switch
// the types.
func (pt ProtoType) Proto() descriptor.FieldDescriptorProto_Type {
	return descriptor.FieldDescriptorProto_Type(pt)
}

// ProtoPtr returns a pointer to the FieldDescriptorProto_Type for this
// ProtoType.
func (pt ProtoType) ProtoPtr() *descriptor.FieldDescriptorProto_Type {
	t := pt.Proto()
	return &t
}

// String returns a string representation of the proto type.
func (pt ProtoType) String() string {
	return pt.Proto().String()
}

package pgs

import (
	"github.com/golang/protobuf/proto"
)

// Entity describes any member of the proto AST that is extensible via
// options. All components of a File are considered entities.
type Entity interface {
	Node

	// The Name of the entity
	Name() Name

	// The fully qualified name of the entity. For example, a message
	// 'HelloRequest' in a 'helloworld' package takes the form of
	// '.helloworld.HelloRequest'.
	FullyQualifiedName() string

	// Syntax identifies whether this entity is encoded with proto2 or proto3
	// syntax.
	Syntax() Syntax

	// Package returns the container package for this entity.
	Package() Package

	// Imports includes external files directly required by this entity. Call
	// TransitiveImports on File to get all transitive dependencies.
	Imports() []File

	// File returns the File containing this entity.
	File() File

	// Extension extracts an extension from the entity's options, described by
	// desc and populates the value ext. Ext must be a pointer type. An error
	// will only be returned if there is a type mismatch between desc and ext.
	// The ok value will be true if the extension was found. If the extension
	// is NOT found, ok will be false and err will be nil.
	Extension(desc *proto.ExtensionDesc, ext interface{}) (ok bool, err error)

	// BuildTarget identifies whether or not generation should be performed on
	// this entity. Use this flag to determine if the file was targeted in the
	// protoc run or if it was loaded as an external dependency.
	BuildTarget() bool

	// SourceCodeInfo returns the SourceCodeInfo associated with the entity.
	// Primarily, this struct contains the comments associated with the Entity.
	SourceCodeInfo() SourceCodeInfo

	childAtPath(path []int32) Entity
	addSourceCodeInfo(info SourceCodeInfo)
}

// A ParentEntity is any Entity type that can contain messages and/or enums.
// File and Message types implement ParentEntity.
type ParentEntity interface {
	Entity

	// Messages returns the top-level messages from this entity. Nested
	// messages are not included.
	Messages() []Message

	// AllMessages returns all the top-level and nested messages from this Entity.
	AllMessages() []Message

	// MapEntries returns the MapEntry message types contained within this
	// Entity. These messages are not returned by the Messages or AllMessages
	// methods. Map Entry messages are typically not exposed to the end user.
	MapEntries() []Message

	// Enums returns the top-level enums from this entity. Nested enums
	// are not included.
	Enums() []Enum

	// AllEnums returns all top-level and nested enums from this entity.
	AllEnums() []Enum

	// DefinedExtensions returns all Extensions defined on this entity.
	DefinedExtensions() []Extension

	addMessage(m Message)
	addMapEntry(m Message)
	addEnum(e Enum)
	addDefExtension(e Extension)
}

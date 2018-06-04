package pgs

import "github.com/golang/protobuf/proto"

// Entity describes any member of the proto AST that is extensible via
// options. All nodes file and below are considered entities.
type Entity interface {
	Node
	Commenter

	// The Name of the entity
	Name() Name

	// The fully qualified name of the entity. For example, a message
	// 'HelloRequest' in a 'helloworld' package it takes the form of
	// '.helloworld.HelloRequest'.
	FullyQualifiedName() string

	// Syntax identifies whether this entity is encoded with proto2 or proto3
	// syntax.
	Syntax() Syntax

	// Package returns the container package for this entity.
	Package() Package

	// Imports includes all external packages required by this entity.
	Imports() []Package

	// File returns the File containing this entity.
	File() File

	// Extension extracts an extension from the entity's options, described by
	// desc and populates the value ext. Ext must be a pointer type. An error is
	// returned if the extension is not found or there is a type mismatch between
	// desc and ext. The ok value will be true if the extension was found.
	Extension(desc *proto.ExtensionDesc, ext interface{}) (ok bool, err error)

	// BuildTarget identifies whether or not generation should be performed on
	// this entity. Use this flag to determine if the file was targeted in the
	// protoc run or if it was loaded as an external dependency.
	BuildTarget() bool
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
	// methods.
	MapEntries() []Message

	// Enums returns the top-level enums from this entity. Nested enums
	// are not included.
	Enums() []Enum

	// AllEnums returns all top-level and nested enums from this entity.
	AllEnums() []Enum

	addMessage(m Message)
	addMapEntry(m Message)
	addEnum(e Enum)
}

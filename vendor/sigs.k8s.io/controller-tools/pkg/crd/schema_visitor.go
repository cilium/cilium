/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package crd

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// SchemaVisitor walks the nodes of a schema.
type SchemaVisitor interface {
	// Visit is called for each schema node.  If it returns a visitor,
	// the visitor will be called on each direct child node, and then
	// this visitor will be called again with `nil` to indicate that
	// all children have been visited.  If a nil visitor is returned,
	// children are not visited.
	//
	// It is *NOT* safe to save references to the given schema.
	// Make deepcopies if you need to keep things around beyond
	// the lifetime of the call.
	Visit(schema *apiextensionsv1.JSONSchemaProps) SchemaVisitor
}

// EditSchema walks the given schema using the given visitor.  Actual
// pointers to each schema node are passed to the visitor, so any changes
// made by the visitor will be reflected to the passed-in schema.
func EditSchema(schema *apiextensionsv1.JSONSchemaProps, visitor SchemaVisitor) {
	walker := schemaWalker{visitor: visitor}
	walker.walkSchema(schema)
}

// schemaWalker knows how to walk the schema, saving modifications
// made by the given visitor.
type schemaWalker struct {
	visitor SchemaVisitor
}

// walkSchema walks the given schema, saving modifications made by the visitor
// (this is as simple as passing a pointer in most cases, but special care
// needs to be taken to persist with maps).  It also visits referenced
// schemata, dealing with circular references appropriately.  The returned
// visitor will be used to visit all "children" of the current schema, followed
// by a nil schema with the returned visitor to mark completion.  If a nil visitor
// is returned, traversal will no continue into the children of the current schema.
func (w schemaWalker) walkSchema(schema *apiextensionsv1.JSONSchemaProps) {
	// Walk a potential chain of schema references, keeping track of seen
	// references to avoid circular references
	subVisitor := w.visitor
	seenRefs := map[string]bool{}
	if schema.Ref != nil {
		seenRefs[*schema.Ref] = true
	}
	for {
		subVisitor = subVisitor.Visit(schema)
		if subVisitor == nil {
			return
		}
		// mark completion of the visitor
		defer subVisitor.Visit(nil)

		// Break if schema is not a reference or a cycle is detected
		if schema.Ref == nil || len(*schema.Ref) == 0 || seenRefs[*schema.Ref] {
			break
		}
		seenRefs[*schema.Ref] = true
	}

	// walk sub-schemata
	subWalker := schemaWalker{visitor: subVisitor}
	if schema.Items != nil {
		subWalker.walkPtr(schema.Items.Schema)
		subWalker.walkSlice(schema.Items.JSONSchemas)
	}
	subWalker.walkSlice(schema.AllOf)
	subWalker.walkSlice(schema.OneOf)
	subWalker.walkSlice(schema.AnyOf)
	subWalker.walkPtr(schema.Not)
	subWalker.walkMap(schema.Properties)
	if schema.AdditionalProperties != nil {
		subWalker.walkPtr(schema.AdditionalProperties.Schema)
	}
	subWalker.walkMap(schema.PatternProperties)
	for name, dep := range schema.Dependencies {
		subWalker.walkPtr(dep.Schema)
		schema.Dependencies[name] = dep
	}
	if schema.AdditionalItems != nil {
		subWalker.walkPtr(schema.AdditionalItems.Schema)
	}
	subWalker.walkMap(schema.Definitions)
}

// walkMap walks over values of the given map, saving changes to them.
func (w schemaWalker) walkMap(defs map[string]apiextensionsv1.JSONSchemaProps) {
	for name, def := range defs {
		// this is iter var reference is because we immediately preseve it below
		//nolint:gosec
		w.walkSchema(&def)
		// make sure the edits actually go through since we can't
		// take a reference to the value in the map
		defs[name] = def
	}
}

// walkSlice walks over items of the given slice.
func (w schemaWalker) walkSlice(defs []apiextensionsv1.JSONSchemaProps) {
	for i := range defs {
		w.walkSchema(&defs[i])
	}
}

// walkPtr walks over the contents of the given pointer, if it's not nil.
func (w schemaWalker) walkPtr(def *apiextensionsv1.JSONSchemaProps) {
	if def == nil {
		return
	}
	w.walkSchema(def)
}

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

package markers

import (
	"go/ast"
	"go/token"
	"reflect"
	"strings"

	"sigs.k8s.io/controller-tools/pkg/loader"
)

// extractDoc extracts documentation from the given node, skipping markers
// in the godoc and falling back to the decl if necessary (for single-line decls).
func extractDoc(node ast.Node, decl *ast.GenDecl) string {
	var docs *ast.CommentGroup
	switch docced := node.(type) {
	case *ast.Field:
		docs = docced.Doc
	case *ast.File:
		docs = docced.Doc
	case *ast.GenDecl:
		docs = docced.Doc
	case *ast.TypeSpec:
		docs = docced.Doc
		// type Ident expr expressions get docs attached to the decl,
		// so check for that case (missing Lparen == single line type decl)
		if docs == nil && decl.Lparen == token.NoPos {
			docs = decl.Doc
		}
	}

	if docs == nil {
		return ""
	}

	// filter out markers
	var outGroup ast.CommentGroup
	outGroup.List = make([]*ast.Comment, 0, len(docs.List))
	for _, comment := range docs.List {
		if isMarkerComment(comment.Text) {
			continue
		}
		outGroup.List = append(outGroup.List, comment)
	}

	// split lines, and re-join together as a single
	// paragraph, respecting double-newlines as
	// paragraph markers.
	outLines := strings.Split(outGroup.Text(), "\n")
	if outLines[len(outLines)-1] == "" {
		// chop off the extraneous last part
		outLines = outLines[:len(outLines)-1]
	}
	// respect double-newline meaning actual newline
	for i, line := range outLines {
		if line == "" {
			outLines[i] = "\n"
		}
	}
	return strings.Join(outLines, " ")
}

// PackageMarkers collects all the package-level marker values for the given package.
func PackageMarkers(col *Collector, pkg *loader.Package) (MarkerValues, error) {
	markers, err := col.MarkersInPackage(pkg)
	if err != nil {
		return nil, err
	}
	res := make(MarkerValues)
	for _, file := range pkg.Syntax {
		fileMarkers := markers[file]
		for name, vals := range fileMarkers {
			res[name] = append(res[name], vals...)
		}
	}

	return res, nil
}

// FieldInfo contains marker values and commonly used information for a struct field.
type FieldInfo struct {
	// Name is the name of the field (or "" for embedded fields)
	Name string
	// Doc is the Godoc of the field, pre-processed to remove markers and joine
	// single newlines together.
	Doc string
	// Tag struct tag associated with this field (or "" if non existed).
	Tag reflect.StructTag

	// Markers are all registered markers associated with this field.
	Markers MarkerValues

	// RawField is the raw, underlying field AST object that this field represents.
	RawField *ast.Field
}

// TypeInfo contains marker values and commonly used information for a type declaration.
type TypeInfo struct {
	// Name is the name of the type.
	Name string
	// Doc is the Godoc of the type, pre-processed to remove markers and joine
	// single newlines together.
	Doc string

	// Markers are all registered markers associated with the type.
	Markers MarkerValues

	// Fields are all the fields associated with the type, if it's a struct.
	// (if not, Fields will be nil).
	Fields []FieldInfo

	// RawDecl contains the raw GenDecl that the type was declared as part of.
	RawDecl *ast.GenDecl
	// RawSpec contains the raw Spec that declared this type.
	RawSpec *ast.TypeSpec
	// RawFile contains the file in which this type was declared.
	RawFile *ast.File
}

// TypeCallback is a callback called for each type declaration in a package.
type TypeCallback func(info *TypeInfo)

// EachType collects all markers, then calls the given callback for each type declaration in a package.
// Each individual spec is considered separate, so
//
//  type (
//      Foo string
//      Bar int
//      Baz struct{}
//  )
//
// yields three calls to the callback.
func EachType(col *Collector, pkg *loader.Package, cb TypeCallback) error {
	markers, err := col.MarkersInPackage(pkg)
	if err != nil {
		return err
	}

	loader.EachType(pkg, func(file *ast.File, decl *ast.GenDecl, spec *ast.TypeSpec) {
		var fields []FieldInfo
		if structSpec, isStruct := spec.Type.(*ast.StructType); isStruct {
			for _, field := range structSpec.Fields.List {
				for _, name := range field.Names {
					fields = append(fields, FieldInfo{
						Name:     name.Name,
						Doc:      extractDoc(field, nil),
						Tag:      loader.ParseAstTag(field.Tag),
						Markers:  markers[field],
						RawField: field,
					})
				}
				if field.Names == nil {
					fields = append(fields, FieldInfo{
						Doc:      extractDoc(field, nil),
						Tag:      loader.ParseAstTag(field.Tag),
						Markers:  markers[field],
						RawField: field,
					})
				}
			}
		}

		cb(&TypeInfo{
			Name:    spec.Name.Name,
			Markers: markers[spec],
			Doc:     extractDoc(spec, decl),
			Fields:  fields,
			RawDecl: decl,
			RawSpec: spec,
			RawFile: file,
		})
	})

	return nil
}

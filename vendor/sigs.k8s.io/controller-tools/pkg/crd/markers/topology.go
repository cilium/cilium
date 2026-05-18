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
	"fmt"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

// TopologyMarkers specify topology markers (i.e. markers that describe if a
// list behaves as an associative-list or a set, if a map is atomic or not).
var TopologyMarkers = []*definitionWithHelp{
	must(markers.MakeDefinition("listMapKey", markers.DescribesField, ListMapKey(""))).
		WithHelp(ListMapKey("").Help()),
	must(markers.MakeDefinition("listMapKey", markers.DescribesType, ListMapKey(""))).
		WithHelp(ListMapKey("").Help()),
	must(markers.MakeDefinition("listType", markers.DescribesField, ListType(""))).
		WithHelp(ListType("").Help()),
	must(markers.MakeDefinition("listType", markers.DescribesType, ListType(""))).
		WithHelp(ListType("").Help()),
	must(markers.MakeDefinition("mapType", markers.DescribesField, MapType(""))).
		WithHelp(MapType("").Help()),
	must(markers.MakeDefinition("mapType", markers.DescribesType, MapType(""))).
		WithHelp(MapType("").Help()),
	must(markers.MakeDefinition("structType", markers.DescribesField, StructType(""))).
		WithHelp(StructType("").Help()),
	must(markers.MakeDefinition("structType", markers.DescribesType, StructType(""))).
		WithHelp(StructType("").Help()),
}

func init() {
	AllDefinitions = append(AllDefinitions, TopologyMarkers...)
}

// +controllertools:marker:generateHelp:category="CRD processing"

// ListType specifies the type of data-structure that the list
// represents (map, set, atomic).
//
// This is important for Server-Side Apply to correctly merge list updates.
//
// Possible data-structure types of a list are:
//
//   - "map": it needs to have a key field, which will be used to build an
//     associative list. A typical example is a the pod container list,
//     which is indexed by the container name.
//
//   - "set": Fields need to be "scalar", and there can be only one
//     occurrence of each.
//
//   - "atomic": All the fields in the list are treated as a single value,
//     are typically manipulated together by the same actor.
//
// Examples:
//
//	// Map list (associative list) - items are merged by key
//	// +listType=map
//	// +listMapKey=name
//	Containers []Container
//
//	// Set list - items must be unique scalars
//	// +listType=set
//	Tags []string
//
//	// Atomic list - entire list is replaced on update
//	// +listType=atomic
//	Args []string
type ListType string

const (
	Map     ListType = "map"
	Set     ListType = "set"
	Atomic  ListType = "atomic"
	Array   ListType = "array"
	Object  ListType = "object"
	Integer ListType = "integer"
	Number  ListType = "number"
)

// +controllertools:marker:generateHelp:category="CRD processing"

// ListMapKey specifies the keys to map listTypes.
//
// It indicates the index of a map list. They can be repeated if multiple keys
// must be used. It can only be used when ListType is set to map, and the keys
// should be scalar types.
//
// Examples:
//
//	// Single key
//	// +listType=map
//	// +listMapKey=name
//	Containers []Container
//
//	// Composite key (multiple keys)
//	// +listType=map
//	// +listMapKey=name
//	// +listMapKey=protocol
//	Ports []Port
type ListMapKey string

// +controllertools:marker:generateHelp:category="CRD processing"

// MapType specifies the level of atomicity of the map;
// i.e. whether each item in the map is independent of the others,
// or all fields are treated as a single unit.
//
// This is important for Server-Side Apply to correctly merge map updates.
//
// Possible values:
//
//   - "granular": items in the map are independent of each other,
//     and can be manipulated by different actors.
//     This is the default behavior.
//
//   - "atomic": all fields are treated as one unit.
//     Any changes have to replace the entire map.
//
// Examples:
//
//	// Granular map (default) - individual keys can be updated independently
//	// +mapType=granular
//	Labels map[string]string
//
//	// Atomic map - entire map is replaced on update
//	// +mapType=atomic
//	Config map[string]string
type MapType string

// +controllertools:marker:generateHelp:category="CRD processing"

// StructType specifies the level of atomicity of the struct;
// i.e. whether each field in the struct is independent of the others,
// or all fields are treated as a single unit.
//
// This is important for Server-Side Apply to correctly merge struct updates.
//
// Possible values:
//
//   - "granular": fields in the struct are independent of each other,
//     and can be manipulated by different actors.
//     This is the default behavior.
//
//   - "atomic": all fields are treated as one unit.
//     Any changes have to replace the entire struct.
//
// Examples:
//
//	// Granular struct (default) - individual fields can be updated independently
//	// +structType=granular
//	type Config struct {
//	    Host string
//	    Port int
//	}
//
//	// Atomic struct - entire struct is replaced on update
//	// +structType=atomic
//	type Credentials struct {
//	    Username string
//	    Password string
//	}
type StructType string

func (l ListType) ApplyToSchema(ctx *SchemaContext, schema *apiextensionsv1.JSONSchemaProps) error {
	if schema.Type != string(Array) {
		return fmt.Errorf("must apply listType to an array, found %s", schema.Type)
	}
	if l != Map && l != Atomic && l != Set {
		return fmt.Errorf(`ListType must be either "map", "set" or "atomic"`)
	}
	p := string(l)
	schema.XListType = &p
	return nil
}

func (l ListType) ApplyPriority() ApplyPriority {
	return ApplyPriorityDefault - 1
}

func (l ListMapKey) ApplyToSchema(ctx *SchemaContext, schema *apiextensionsv1.JSONSchemaProps) error {
	if schema.Type != string(Array) {
		return fmt.Errorf("must apply listMapKey to an array, found %s", schema.Type)
	}
	if schema.XListType == nil || *schema.XListType != string(Map) {
		return fmt.Errorf("must apply listMapKey to an associative-list")
	}
	schema.XListMapKeys = append(schema.XListMapKeys, string(l))
	return nil
}

func (m MapType) ApplyToSchema(ctx *SchemaContext, schema *apiextensionsv1.JSONSchemaProps) error {
	if schema.Type != string(Object) {
		return fmt.Errorf("must apply mapType to an object")
	}

	if m != "atomic" && m != "granular" {
		return fmt.Errorf(`MapType must be either "granular" or "atomic"`)
	}

	p := string(m)
	schema.XMapType = &p

	return nil
}

func (s StructType) ApplyToSchema(ctx *SchemaContext, schema *apiextensionsv1.JSONSchemaProps) error {
	if schema.Type != string(Object) && schema.Type != "" {
		return fmt.Errorf("must apply structType to an object; either explicitly set or defaulted through an empty schema type")
	}

	if s != "atomic" && s != "granular" {
		return fmt.Errorf(`StructType must be either "granular" or "atomic"`)
	}

	p := string(s)
	schema.XMapType = &p

	return nil
}

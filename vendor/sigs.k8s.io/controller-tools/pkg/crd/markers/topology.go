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

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
type ListType string

// +controllertools:marker:generateHelp:category="CRD processing"

// ListMapKey specifies the keys to map listTypes.
//
// It indicates the index of a map list. They can be repeated if multiple keys
// must be used. It can only be used when ListType is set to map, and the keys
// should be scalar types.
type ListMapKey string

// +controllertools:marker:generateHelp:category="CRD processing"

// MapType specifies the level of atomicity of the map;
// i.e. whether each item in the map is independent of the others,
// or all fields are treated as a single unit.
//
// Possible values:
//
//   - "granular": items in the map are independent of each other,
//     and can be manipulated by different actors.
//     This is the default behavior.
//
//   - "atomic": all fields are treated as one unit.
//     Any changes have to replace the entire map.
type MapType string

// +controllertools:marker:generateHelp:category="CRD processing"

// StructType specifies the level of atomicity of the struct;
// i.e. whether each field in the struct is independent of the others,
// or all fields are treated as a single unit.
//
// Possible values:
//
//   - "granular": fields in the struct are independent of each other,
//     and can be manipulated by different actors.
//     This is the default behavior.
//
//   - "atomic": all fields are treated as one unit.
//     Any changes have to replace the entire struct.
type StructType string

func (l ListType) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "array" {
		return fmt.Errorf("must apply listType to an array, found %s", schema.Type)
	}
	if l != "map" && l != "atomic" && l != "set" {
		return fmt.Errorf(`ListType must be either "map", "set" or "atomic"`)
	}
	p := string(l)
	schema.XListType = &p
	return nil
}

func (l ListType) ApplyPriority() ApplyPriority {
	return ApplyPriorityDefault - 1
}

func (l ListMapKey) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "array" {
		return fmt.Errorf("must apply listMapKey to an array, found %s", schema.Type)
	}
	if schema.XListType == nil || *schema.XListType != "map" {
		return fmt.Errorf("must apply listMapKey to an associative-list")
	}
	schema.XListMapKeys = append(schema.XListMapKeys, string(l))
	return nil
}

func (m MapType) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "object" {
		return fmt.Errorf("must apply mapType to an object")
	}

	if m != "atomic" && m != "granular" {
		return fmt.Errorf(`MapType must be either "granular" or "atomic"`)
	}

	p := string(m)
	schema.XMapType = &p

	return nil
}

func (s StructType) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "object" && schema.Type != "" {
		return fmt.Errorf("must apply structType to an object; either explicitly set or defaulted through an empty schema type")
	}

	if s != "atomic" && s != "granular" {
		return fmt.Errorf(`StructType must be either "granular" or "atomic"`)
	}

	p := string(s)
	schema.XMapType = &p

	return nil
}

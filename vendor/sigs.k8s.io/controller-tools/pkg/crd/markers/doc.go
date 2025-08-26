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

// Package markers defines markers for generating schema valiation
// and CRD structure.
//
// All markers related to CRD generation live in AllDefinitions.
//
// # Validation Markers
//
// Validation markers have values that implement ApplyToSchema
// (crd.SchemaMarker).  Any marker implementing this will automatically
// be run after the rest of a given schema node has been generated.
// Markers that need to be run before any other markers can also
// implement ApplyFirst, but this is discouraged and may change
// in the future. It is recommended to implement the ApplyPriority
// interface in combination with ApplyPriorityDefault and
// ApplyPriorityFirst constants. Following is an example of how to
// implement such a marker:
//
//	type MyCustomMarker string
//
//	func (m MyCustomMarker) ApplyPriority() ApplyPriority {
//		return ApplyPriorityFirst
//	}
//
//	func (m MyCustomMarker) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
//	  ...
//	}
//
// All validation markers start with "+kubebuilder:validation", and
// have the same name as their type name.
//
// # CRD Markers
//
// Markers that modify anything in the CRD itself *except* for the schema
// implement ApplyToCRD (crd.SpecMarker).  They are expected to detect whether
// they should apply themselves to a specific version in the CRD (as passed to
// them), or to the root-level CRD for legacy cases.  They are applied *after*
// the rest of the CRD is computed.
//
// # Misc
//
// This package also defines the "+groupName" and "+versionName" package-level
// markers, for defining package<->group-version mappings.
package markers

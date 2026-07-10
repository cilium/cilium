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

// You *probably* don't want to write these structs by hand
// -- use cmd/helpgen if you can write Godoc, and {Simple,Deprecated}Help
// otherwise.

// DetailedHelp contains brief help, as well as more details.
// For the "full" help, join the two together.
type DetailedHelp struct {
	Summary string
	Details string
}

// DefinitionHelp contains overall help for a marker Definition,
// as well as per-field help.
type DefinitionHelp struct {
	// DetailedHelp contains the overall help for the marker.
	DetailedHelp
	// Category describes what kind of marker this is.
	Category string
	// DeprecatedInFavorOf marks the marker as deprecated.
	// If non-nil & empty, it's assumed to just mean deprecated permanently.
	// If non-empty, it's assumed to be a marker name.
	DeprecatedInFavorOf *string

	// NB(directxman12): we make FieldHelp be in terms of the Go struct field
	// names so that we don't have to know the conversion or processing rules
	// for struct fields at compile-time for help generation.

	// FieldHelp defines the per-field help for this marker, *in terms of the
	// go struct field names.  Use the FieldsHelp method to map this to
	// marker argument names.
	FieldHelp map[string]DetailedHelp
}

// FieldsHelp maps per-field help to the actual marker argument names from the
// given definition.
func (d *DefinitionHelp) FieldsHelp(def *Definition) map[string]DetailedHelp {
	fieldsHelp := make(map[string]DetailedHelp, len(def.FieldNames))
	for fieldName, argName := range def.FieldNames {
		fieldsHelp[fieldName] = d.FieldHelp[argName]
	}
	return fieldsHelp
}

// SimpleHelp returns help that just has marker-level summary information
// (e.g. for use with empty or primitive-typed markers, where Godoc-based
// generation isn't possible).
func SimpleHelp(category, summary string) *DefinitionHelp {
	return &DefinitionHelp{
		Category:     category,
		DetailedHelp: DetailedHelp{Summary: summary},
	}
}

// DeprecatedHelp returns simple help (a la SimpleHelp), except marked as
// deprecated in favor of the given marker (or an empty string for just
// deprecated).
func DeprecatedHelp(inFavorOf, category, summary string) *DefinitionHelp {
	return &DefinitionHelp{
		Category:            category,
		DetailedHelp:        DetailedHelp{Summary: summary},
		DeprecatedInFavorOf: &inFavorOf,
	}
}

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

package help

import (
	"slices"
	"strings"

	"sigs.k8s.io/controller-tools/pkg/markers"
)

// DetailedHelp contains both a summary and further details.
type DetailedHelp struct {
	// Summary contains a one-line description.
	Summary string `json:"summary"`
	// Details contains further information.
	Details string `json:"details,omitempty"`
}

// Argument is the type data for a marker argument.
type Argument struct {
	// Type is the data type of the argument (string, bool, int, slice, any, raw, invalid)
	Type string `json:"type"`
	// Optional marks this argument as optional.
	Optional bool `json:"optional"`
	// ItemType contains the type of the slice item, if this is a slice
	ItemType *Argument `json:"itemType,omitempty"`
}

func (a Argument) typeString(out *strings.Builder) {
	if a.Type == "slice" {
		out.WriteString("[]")
		a.ItemType.typeString(out)
		return
	}

	out.WriteString(a.Type)
}

// TypeString returns a string roughly equivalent
// (but not identical) to the underlying Go type that
// this argument would parse to.  It's mainly useful
// for user-friendly formatting of this argument (e.g.
// help strings).
func (a Argument) TypeString() string {
	out := &strings.Builder{}
	a.typeString(out)
	return out.String()
}

// FieldHelp contains information required to print documentation for a marker field.
type FieldHelp struct {
	// Name is the field name.
	Name string `json:"name"`
	// Argument is the type of the field.
	Argument `json:",inline"`

	// DetailedHelp contains the textual help for the field.
	DetailedHelp `json:",inline"`
}

// MarkerDoc contains information required to print documentation for a marker.
type MarkerDoc struct {
	// definition

	// Name is the name of the marker.
	Name string `json:"name"`
	// Target is the target (field, package, type) of the marker.
	Target string `json:"target"`

	// help

	// DetailedHelp is the textual help for the marker.
	DetailedHelp `json:",inline"`
	// Category is the general "category" that this marker belongs to.
	Category string `json:"category"`
	// DeprecatedInFavorOf marks that this marker shouldn't be used when
	// non-nil.  If also non-empty, another marker should be used instead.
	DeprecatedInFavorOf *string `json:"deprecatedInFavorOf,omitempty"`
	// Fields is the type and help data for each field of this marker.
	Fields []FieldHelp `json:"fields,omitempty"`
}

// Empty checks if this marker has any arguments, returning true if not.
func (m MarkerDoc) Empty() bool {
	return len(m.Fields) == 0
}

// AnonymousField chekcs if this is an single-valued marker
// (as opposed to having named fields).
func (m MarkerDoc) AnonymousField() bool {
	return len(m.Fields) == 1 && m.Fields[0].Name == ""
}

// ForArgument returns the equivalent documentation for a marker argument.
func ForArgument(argRaw markers.Argument) Argument {
	res := Argument{
		Optional: argRaw.Optional,
	}

	if argRaw.ItemType != nil {
		itemType := ForArgument(*argRaw.ItemType)
		res.ItemType = &itemType
	}

	switch argRaw.Type {
	case markers.IntType:
		res.Type = "int"
	case markers.StringType:
		res.Type = "string"
	case markers.BoolType:
		res.Type = "bool"
	case markers.AnyType:
		res.Type = "any"
	case markers.SliceType:
		res.Type = "slice"
	case markers.RawType:
		res.Type = "raw"
	case markers.InvalidType:
		res.Type = "invalid"
	}

	return res
}

// ForDefinition returns the equivalent marker documentation for a given marker definition and spearate help.
func ForDefinition(defn *markers.Definition, maybeHelp *markers.DefinitionHelp) MarkerDoc {
	var help markers.DefinitionHelp
	if maybeHelp != nil {
		help = *maybeHelp
	}

	res := MarkerDoc{
		Name:                defn.Name,
		Category:            help.Category,
		DeprecatedInFavorOf: help.DeprecatedInFavorOf,
		Target:              defn.Target.String(),
		DetailedHelp:        DetailedHelp{Summary: help.Summary, Details: help.Details},
	}

	helpByField := help.FieldsHelp(defn)

	// TODO(directxman12): deterministic ordering
	for fieldName, fieldHelpRaw := range helpByField {
		fieldInfo := defn.Fields[fieldName]
		fieldHelp := FieldHelp{
			Name:         fieldName,
			DetailedHelp: DetailedHelp{Summary: fieldHelpRaw.Summary, Details: fieldHelpRaw.Details},
			Argument:     ForArgument(fieldInfo),
		}

		res.Fields = append(res.Fields, fieldHelp)
	}

	slices.SortStableFunc(res.Fields, func(a, b FieldHelp) int { return strings.Compare(a.Name, b.Name) })

	return res
}

// CategoryDoc contains help information for all markers in a Category.
type CategoryDoc struct {
	Category string      `json:"category"`
	Markers  []MarkerDoc `json:"markers"`
}

// ByCategory returns the marker help for markers in the given
// registry, grouped and sorted according to the given method.
func ByCategory(reg *markers.Registry, sorter SortGroup) []CategoryDoc {
	groupedMarkers := make(map[string][]*markers.Definition)

	for _, marker := range reg.AllDefinitions() {
		group := sorter.Group(marker, reg.HelpFor(marker))
		groupedMarkers[group] = append(groupedMarkers[group], marker)
	}
	allGroups := make([]string, 0, len(groupedMarkers))
	for groupName := range groupedMarkers {
		allGroups = append(allGroups, groupName)
	}

	slices.Sort(allGroups)

	res := make([]CategoryDoc, len(allGroups))
	for i, groupName := range allGroups {
		mks := groupedMarkers[groupName]
		slices.SortStableFunc(mks, func(a, b *markers.Definition) int {
			return sorter.Compare(a, b)
		})

		markerDocs := make([]MarkerDoc, len(mks))
		for i, marker := range mks {
			markerDocs[i] = ForDefinition(marker, reg.HelpFor(marker))
		}

		res[i] = CategoryDoc{
			Category: groupName,
			Markers:  markerDocs,
		}
	}

	return res
}

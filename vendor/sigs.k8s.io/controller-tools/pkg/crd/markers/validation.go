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

	"encoding/json"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"sigs.k8s.io/controller-tools/pkg/markers"
)

// ValidationMarkers lists all available markers that affect CRD schema generation,
// except for the few that don't make sense as type-level markers (see FieldOnlyMarkers).
// All markers start with `+kubebuilder:validation:`, and continue with their type name.
// A copy is produced of all markers that describes types as well, for making types
// reusable and writing complex validations on slice items.
var ValidationMarkers = mustMakeAllWithPrefix("kubebuilder:validation", markers.DescribesField,

	// integer markers

	Maximum(0),
	Minimum(0),
	ExclusiveMaximum(false),
	ExclusiveMinimum(false),
	MultipleOf(0),
	MinProperties(0),
	MaxProperties(0),

	// string markers

	MaxLength(0),
	MinLength(0),
	Pattern(""),

	// slice markers

	MaxItems(0),
	MinItems(0),
	UniqueItems(false),

	// general markers

	Enum(nil),
	Format(""),
	Type(""),
	XPreserveUnknownFields{},
	XEmbeddedResource{},
)

// FieldOnlyMarkers list field-specific validation markers (i.e. those markers that don't make
// sense on a type, and thus aren't in ValidationMarkers).
var FieldOnlyMarkers = []*definitionWithHelp{
	must(markers.MakeDefinition("kubebuilder:validation:Required", markers.DescribesField, struct{}{})).
		WithHelp(markers.SimpleHelp("CRD validation", "specifies that this field is required, if fields are optional by default.")),
	must(markers.MakeDefinition("kubebuilder:validation:Optional", markers.DescribesField, struct{}{})).
		WithHelp(markers.SimpleHelp("CRD validation", "specifies that this field is optional, if fields are required by default.")),
	must(markers.MakeDefinition("optional", markers.DescribesField, struct{}{})).
		WithHelp(markers.SimpleHelp("CRD validation", "specifies that this field is optional, if fields are required by default.")),

	must(markers.MakeDefinition("nullable", markers.DescribesField, Nullable{})).
		WithHelp(Nullable{}.Help()),

	must(markers.MakeAnyTypeDefinition("kubebuilder:default", markers.DescribesField, Default{})).
		WithHelp(Default{}.Help()),

	must(markers.MakeDefinition("kubebuilder:validation:EmbeddedResource", markers.DescribesField, XEmbeddedResource{})).
		WithHelp(XEmbeddedResource{}.Help()),
}

// ValidationIshMarkers are field-and-type markers that don't fall under the
// :validation: prefix, and/or don't have a name that directly matches their
// type.
var ValidationIshMarkers = []*definitionWithHelp{
	must(markers.MakeDefinition("kubebuilder:pruning:PreserveUnknownFields", markers.DescribesField, XPreserveUnknownFields{})).
		WithHelp(XPreserveUnknownFields{}.Help()),
	must(markers.MakeDefinition("kubebuilder:pruning:PreserveUnknownFields", markers.DescribesType, XPreserveUnknownFields{})).
		WithHelp(XPreserveUnknownFields{}.Help()),
}

func init() {
	AllDefinitions = append(AllDefinitions, ValidationMarkers...)

	for _, def := range ValidationMarkers {
		newDef := *def.Definition
		// copy both parts so we don't change the definition
		typDef := definitionWithHelp{
			Definition: &newDef,
			Help:       def.Help,
		}
		typDef.Target = markers.DescribesType
		AllDefinitions = append(AllDefinitions, &typDef)
	}

	AllDefinitions = append(AllDefinitions, FieldOnlyMarkers...)
	AllDefinitions = append(AllDefinitions, ValidationIshMarkers...)
}

// +controllertools:marker:generateHelp:category="CRD validation"
// Maximum specifies the maximum numeric value that this field can have.
type Maximum int

// +controllertools:marker:generateHelp:category="CRD validation"
// Minimum specifies the minimum numeric value that this field can have. Negative integers are supported.
type Minimum int

// +controllertools:marker:generateHelp:category="CRD validation"
// ExclusiveMinimum indicates that the minimum is "up to" but not including that value.
type ExclusiveMinimum bool

// +controllertools:marker:generateHelp:category="CRD validation"
// ExclusiveMaximum indicates that the maximum is "up to" but not including that value.
type ExclusiveMaximum bool

// +controllertools:marker:generateHelp:category="CRD validation"
// MultipleOf specifies that this field must have a numeric value that's a multiple of this one.
type MultipleOf int

// +controllertools:marker:generateHelp:category="CRD validation"
// MaxLength specifies the maximum length for this string.
type MaxLength int

// +controllertools:marker:generateHelp:category="CRD validation"
// MinLength specifies the minimum length for this string.
type MinLength int

// +controllertools:marker:generateHelp:category="CRD validation"
// Pattern specifies that this string must match the given regular expression.
type Pattern string

// +controllertools:marker:generateHelp:category="CRD validation"
// MaxItems specifies the maximum length for this list.
type MaxItems int

// +controllertools:marker:generateHelp:category="CRD validation"
// MinItems specifies the minimun length for this list.
type MinItems int

// +controllertools:marker:generateHelp:category="CRD validation"
// UniqueItems specifies that all items in this list must be unique.
type UniqueItems bool

// +controllertools:marker:generateHelp:category="CRD validation"
// MaxProperties restricts the number of keys in an object
type MaxProperties int

// +controllertools:marker:generateHelp:category="CRD validation"
// MinProperties restricts the number of keys in an object
type MinProperties int

// +controllertools:marker:generateHelp:category="CRD validation"
// Enum specifies that this (scalar) field is restricted to the *exact* values specified here.
type Enum []interface{}

// +controllertools:marker:generateHelp:category="CRD validation"
// Format specifies additional "complex" formatting for this field.
//
// For example, a date-time field would be marked as "type: string" and
// "format: date-time".
type Format string

// +controllertools:marker:generateHelp:category="CRD validation"
// Type overrides the type for this field (which defaults to the equivalent of the Go type).
//
// This generally must be paired with custom serialization.  For example, the
// metav1.Time field would be marked as "type: string" and "format: date-time".
type Type string

// +controllertools:marker:generateHelp:category="CRD validation"
// Nullable marks this field as allowing the "null" value.
//
// This is often not necessary, but may be helpful with custom serialization.
type Nullable struct{}

// +controllertools:marker:generateHelp:category="CRD validation"
// Default sets the default value for this field.
//
// A default value will be accepted as any value valid for the
// field. Formatting for common types include: boolean: `true`, string:
// `Cluster`, numerical: `1.24`, array: `{1,2}`, object: `{policy:
// "delete"}`). Defaults should be defined in pruned form, and only best-effort
// validation will be performed. Full validation of a default requires
// submission of the containing CRD to an apiserver.
type Default struct {
	Value interface{}
}

// +controllertools:marker:generateHelp:category="CRD processing"
// PreserveUnknownFields stops the apiserver from pruning fields which are not specified.
//
// By default the apiserver drops unknown fields from the request payload
// during the decoding step. This marker stops the API server from doing so.
// It affects fields recursively, but switches back to normal pruning behaviour
// if nested  properties or additionalProperties are specified in the schema.
// This can either be true or undefined. False
// is forbidden.
//
// NB: The kubebuilder:validation:XPreserveUnknownFields variant is deprecated
// in favor of the kubebuilder:pruning:PreserveUnknownFields variant.  They function
// identically.
type XPreserveUnknownFields struct{}

// +controllertools:marker:generateHelp:category="CRD validation"
// EmbeddedResource marks a fields as an embedded resource with apiVersion, kind and metadata fields.
//
// An embedded resource is a value that has apiVersion, kind and metadata fields.
// They are validated implicitly according to the semantics of the currently
// running apiserver. It is not necessary to add any additional schema for these
// field, yet it is possible. This can be combined with PreserveUnknownFields.
type XEmbeddedResource struct{}

func (m Maximum) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "integer" {
		return fmt.Errorf("must apply maximum to an integer")
	}
	val := float64(m)
	schema.Maximum = &val
	return nil
}
func (m Minimum) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "integer" {
		return fmt.Errorf("must apply minimum to an integer")
	}
	val := float64(m)
	schema.Minimum = &val
	return nil
}
func (m ExclusiveMaximum) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "integer" {
		return fmt.Errorf("must apply exclusivemaximum to an integer")
	}
	schema.ExclusiveMaximum = bool(m)
	return nil
}
func (m ExclusiveMinimum) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "integer" {
		return fmt.Errorf("must apply exclusiveminimum to an integer")
	}
	schema.ExclusiveMinimum = bool(m)
	return nil
}
func (m MultipleOf) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "integer" {
		return fmt.Errorf("must apply multipleof to an integer")
	}
	val := float64(m)
	schema.MultipleOf = &val
	return nil
}

func (m MaxLength) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "string" {
		return fmt.Errorf("must apply maxlength to a string")
	}
	val := int64(m)
	schema.MaxLength = &val
	return nil
}
func (m MinLength) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "string" {
		return fmt.Errorf("must apply minlength to a string")
	}
	val := int64(m)
	schema.MinLength = &val
	return nil
}
func (m Pattern) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "string" {
		return fmt.Errorf("must apply pattern to a string")
	}
	schema.Pattern = string(m)
	return nil
}

func (m MaxItems) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "array" {
		return fmt.Errorf("must apply maxitem to an array")
	}
	val := int64(m)
	schema.MaxItems = &val
	return nil
}
func (m MinItems) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "array" {
		return fmt.Errorf("must apply minitems to an array")
	}
	val := int64(m)
	schema.MinItems = &val
	return nil
}
func (m UniqueItems) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "array" {
		return fmt.Errorf("must apply uniqueitems to an array")
	}
	schema.UniqueItems = bool(m)
	return nil
}

func (m MinProperties) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "object" {
		return fmt.Errorf("must apply minproperties to an object")
	}
	val := int64(m)
	schema.MinProperties = &val
	return nil
}

func (m MaxProperties) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "object" {
		return fmt.Errorf("must apply maxproperties to an object")
	}
	val := int64(m)
	schema.MaxProperties = &val
	return nil
}

func (m Enum) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	// TODO(directxman12): this is a bit hacky -- we should
	// probably support AnyType better + using the schema structure
	vals := make([]apiext.JSON, len(m))
	for i, val := range m {
		// TODO(directxman12): check actual type with schema type?
		// if we're expecting a string, marshal the string properly...
		// NB(directxman12): we use json.Marshal to ensure we handle JSON escaping properly
		valMarshalled, err := json.Marshal(val)
		if err != nil {
			return err
		}
		vals[i] = apiext.JSON{Raw: valMarshalled}
	}
	schema.Enum = vals
	return nil
}
func (m Format) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	schema.Format = string(m)
	return nil
}

// NB(directxman12): we "typecheck" on target schema properties here,
// which means the "Type" marker *must* be applied first.
// TODO(directxman12): find a less hacky way to do this
// (we could preserve ordering of markers, but that feels bad in its own right).

func (m Type) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	schema.Type = string(m)
	return nil
}

func (m Type) ApplyFirst() {}

func (m Nullable) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	schema.Nullable = true
	return nil
}

// Defaults are only valid CRDs created with the v1 API
func (m Default) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	marshalledDefault, err := json.Marshal(m.Value)
	if err != nil {
		return err
	}
	schema.Default = &apiext.JSON{Raw: marshalledDefault}
	return nil
}

func (m XPreserveUnknownFields) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	defTrue := true
	schema.XPreserveUnknownFields = &defTrue
	return nil
}

func (m XEmbeddedResource) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	schema.XEmbeddedResource = true
	return nil
}

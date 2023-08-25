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

// Package markers contains utilities for defining and parsing "marker
// comments", also occasionally called tag comments (we use the term marker to
// avoid confusing with struct tags).  Parsed result (output) values take the
// form of Go values, much like the "encoding/json" package.
//
// Definitions and Parsing
//
// Markers are defined as structured Definitions which can be used to
// consistently parse marker comments.  A Definition contains an concrete
// output type for the marker, which can be a simple type (like string), a
// struct, or a wrapper type (useful for defining additional methods on marker
// types).
//
// Markers take the general form
//
//  +path:to:marker=val
//
//  +path:to:marker:arg1=val,arg2=val2
//
//  +path:to:marker
//
// Arguments may be ints, bools, strings, and slices.  Ints and bool take their
// standard form from Go.  Strings may take any of their standard forms, or any
// sequence of unquoted characters up until a `,` or `;` is encountered.  Lists
// take either of the following forms:
//
//  val;val;val
//
//  {val, val, val}
//
// Note that the first form will not properly parse nested slices, but is
// generally convenient and is the form used in many existing markers.
//
// Each of those argument types maps to the corresponding go type.  Pointers
// mark optional fields (a struct tag, below, may also be used).  The empty
// interface will match any type.
//
// Struct fields may optionally be annotated with the `marker` struct tag.  The
// first argument is a name override.  If it's left blank (or the tag isn't
// present), the camelCase version of the name will be used.  The only
// additional argument defined is `optional`, which marks a field as optional
// without using a pointer.
//
// All parsed values are unmarshalled into the output type.  If any
// non-optional fields aren't mentioned, an error will be raised unless
// `Strict` is set to false.
//
// Registries and Lookup
//
// Definitions can be added to registries to facilitate lookups.  Each
// definition is marked as either describing a type, struct field, or package
// (unassociated).  The same marker name may be registered multiple times, as
// long as each describes a different construct (type, field, or package).
// Definitions can then be looked up by passing unparsed markers.
//
// Collection and Extraction
//
// Markers can be collected from a loader.Package using a Collector.  The
// Collector will read from a given Registry, collecting comments that look
// like markers and parsing them if they match some definition on the registry.
//
// Markers are considered associated with a particular field or type if they
// exist in the Godoc, or the closest non-godoc comment.  Any other markers not
// inside a some other block (e.g. a struct definition, interface definition,
// etc) are considered package level.  Markers in a "closest non-Go comment
// block" may also be considered package level if registered as such and no
// identical type-level definition exists.
//
// Like loader.Package, Collector's methods are idempotent and will not
// reperform work.
//
// Traversal
//
// EachType function iterates over each type in a Package, providing
// conveniently structured type and field information with marker values
// associated.
//
// PackageMarkers can be used to fetch just package-level markers.
//
// Help
//
// Help can be defined for each marker using the DefinitionHelp struct.  It's
// mostly intended to be generated off of godocs using cmd/helpgen, which takes
// the first line as summary (removing the type/field name), and considers the
// rest as details.  It looks for the
//
//   +controllertools:generateHelp[:category=<string>]
//
// marker to start generation.
//
// If you can't use godoc-based generation for whatever reasons (e.g.
// primitive-typed markers), you can use the SimpleHelp and DeprecatedHelp
// helper functions to generate help structs.
//
// Help is then registered into a registry as associated with the actual
// definition, and can then be later retrieved from the registry.
package markers

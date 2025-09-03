// Copyright 2015 go-swagger maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package swag contains a bunch of helper functions for go-openapi and go-swagger projects.
//
// You may also use it standalone for your projects.
//
// NOTE: all features that were previously exposed as package-level members (constants, variables,
// functions and types) are now deprecated and are superseded by equivalent features in
// more specialized sub-packages.
//
// Here is what is inside:
//
// Module [cmdutils]:
//
//   - utilities to work with CLIs
//
// Module [conv]:
//
//   - convert between value and pointers for builtin types
//   - convert from string to builtin types (wraps strconv)
//
// Module [fileutils]:
//
//   - file upload type
//   - search in path
//
// Module [jsonname]:
//
//   - json names for go properties
//
// Module [jsonutils]:
//
//   - fast json concatenation
//   - read and write JSON from and to dynamic go data structures
//
// Module [loading]:
//
//   - load from file or http
//
// Module [mangling]:
//
//   - name mangling to generate clean identifiers
//
// Module [netutils]:
//
//   - host, port from address
//
// Module [stringutils]:
//
//   - find string in list
//   - join/split arrays of query parameters
//
// Module [typeutils]:
//
//   - check the zero value of any type
//
// Module [yamlutils]:
//
//   - converting YAML to JSON
//   - loading YAML into a dynamic YAML document
//
// This repo has a few dependencies outside of the standard library:
//
//   - YAML utilities depend on [gopkg.in/yaml.v3]
//   - JSON utilities depend on [github.com/mailru/easyjson]
package swag

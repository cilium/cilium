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
	"strings"
	"unicode"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// TruncateDescription truncates the description of fields in given schema if it
// exceeds maxLen.
// It tries to chop off the description at the closest sentence boundary.
func TruncateDescription(schema *apiextensionsv1.JSONSchemaProps, maxLen int) {
	EditSchema(schema, descVisitor{maxLen: maxLen})
}

// descVisitor recursively visits all fields in the schema and truncates the
// description of the fields to specified maxLen.
type descVisitor struct {
	// maxLen is the maximum allowed length for description of a field
	maxLen int
}

func (v descVisitor) Visit(schema *apiextensionsv1.JSONSchemaProps) SchemaVisitor {
	if schema == nil {
		return v
	}
	if v.maxLen < 0 {
		return nil /* no further work to be done for this schema */
	}
	if v.maxLen == 0 {
		schema.Description = ""
		return v
	}
	if len(schema.Description) > v.maxLen {
		schema.Description = truncateString(schema.Description, v.maxLen)
		return v
	}
	return v
}

// truncateString truncates given desc string if it exceeds maxLen. It may
// return string with length less than maxLen even in cases where original desc
// exceeds maxLen because it tries to chop off the desc at the closest sentence
// boundary to avoid incomplete sentences.
func truncateString(desc string, maxLen int) string {
	if len(desc) <= maxLen {
		return desc
	}

	desc = desc[0:maxLen]

	// Trying to chop off at closest sentence boundary.
	if n := strings.LastIndexFunc(desc, isSentenceTerminal); n > 0 {
		return desc[0 : n+1]
	}

	// Trying to chop off at closest word boundary (i.e. whitespace).
	if n := strings.LastIndexFunc(desc, isWhiteSpace); n > 0 {
		return desc[0:n] + "..."
	}

	return desc[0:maxLen] + "..."
}

// helper function to determine if given rune is a sentence terminal or not.
func isSentenceTerminal(r rune) bool {
	return unicode.Is(unicode.STerm, r)
}

// helper function to determine if given rune is whitespace or not.
func isWhiteSpace(r rune) bool {
	return unicode.Is(unicode.White_Space, r)
}

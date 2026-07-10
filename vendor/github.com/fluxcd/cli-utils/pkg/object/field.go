// Copyright 2021 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package object

import (
	"fmt"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// NestedField gets a value from a KRM map, if it exists, otherwise nil.
// Fields can be string (map key) or int (array index).
func NestedField(obj map[string]interface{}, fields ...interface{}) (interface{}, bool, error) {
	var val interface{} = obj

	for i, field := range fields {
		if val == nil {
			return nil, false, nil
		}
		switch typedField := field.(type) {
		case string:
			if m, ok := val.(map[string]interface{}); ok {
				val, ok = m[typedField]
				if !ok {
					// not in map
					return nil, false, nil
				}
			} else {
				return nil, false, InvalidType(fields[:i+1], val, "map[string]interface{}")
			}
		case int:
			if s, ok := val.([]interface{}); ok {
				if typedField >= len(s) {
					// index out of range
					return nil, false, nil
				}
				val = s[typedField]
			} else {
				return nil, false, InvalidType(fields[:i+1], val, "[]interface{}")
			}
		default:
			return nil, false, InvalidType(fields[:i+1], val, "string or int")
		}
	}
	return val, true, nil
}

// InvalidType returns a *Error indicating "invalid value type".  This is used
// to report malformed values (e.g. found int, expected string).
func InvalidType(fieldPath []interface{}, value interface{}, validTypes string) *field.Error {
	return Invalid(fieldPath, value,
		fmt.Sprintf("found type %T, expected %s", value, validTypes))
}

// Invalid returns a *Error indicating "invalid value".  This is used
// to report malformed values (e.g. failed regex match, too long, out of bounds).
func Invalid(fieldPath []interface{}, value interface{}, detail string) *field.Error {
	return &field.Error{
		Type:     field.ErrorTypeInvalid,
		Field:    FieldPath(fieldPath),
		BadValue: value,
		Detail:   detail,
	}
}

// NotFound returns a *Error indicating "value not found".  This is
// used to report failure to find a requested value (e.g. looking up an ID).
func NotFound(fieldPath []interface{}, value interface{}) *field.Error {
	return &field.Error{
		Type:     field.ErrorTypeNotFound,
		Field:    FieldPath(fieldPath),
		BadValue: value,
		Detail:   "",
	}
}

// FieldPath formats a list of KRM field keys as a JSONPath expression.
// The only valid field keys in KRM are strings (map keys) and ints (list keys).
// Simple strings (see isSimpleString) will be delimited with a period.
// Complex strings will be wrapped with square brackets and double quotes.
// Integers will be wrapped with square brackets.
// All other types will be formatted best-effort within square brackets.
func FieldPath(fieldPath []interface{}) string {
	var sb strings.Builder
	for _, field := range fieldPath {
		switch typedField := field.(type) {
		case string:
			if isSimpleString(typedField) {
				_, _ = fmt.Fprintf(&sb, ".%s", typedField)
			} else {
				_, _ = fmt.Fprintf(&sb, "[%q]", typedField)
			}
		case int:
			_, _ = fmt.Fprintf(&sb, "[%d]", typedField)
		default:
			// invalid type. try anyway...
			_, _ = fmt.Fprintf(&sb, "[%#v]", typedField)
		}
	}
	return sb.String()
}

var simpleStringRegex = regexp.MustCompile(`^[a-zA-Z]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$`)

// isSimpleString returns true if the input follows the following rules:
// - contains only alphanumeric characters, '_' or '-'
// - starts with an alphabetic character
// - ends with an alphanumeric character
func isSimpleString(s string) bool {
	return simpleStringRegex.FindString(s) != ""
}

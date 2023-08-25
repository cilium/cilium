// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package checker

import (
	"fmt"
	"reflect"
	"regexp"

	check "github.com/cilium/checkmate"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/cilium/cilium/pkg/comparator"
)

type diffChecker struct {
	*check.CheckerInfo
}

// DeepEquals is a GoCheck checker that does a diff between two objects and
// pretty-prints any difference between the two. It can act as a substitute
// for DeepEquals.
var (
	defaultParams               = []string{"obtained", "expected"}
	DeepEquals    check.Checker = &diffChecker{
		&check.CheckerInfo{Name: "Diff", Params: defaultParams},
	}
)

// Check performs a diff between two objects provided as parameters, and
// returns either true if the objects are identical, or false otherwise. If
// it returns false, it also returns the unified diff between the expected
// and obtained output.
func (checker *diffChecker) Check(params []interface{}, names []string) (result bool, error string) {
	if len(params) != 2 || len(names) != 2 {
		return false, "params and names must be of length 2"
	}

	if reflect.DeepEqual(params[0], params[1]) {
		return true, ""
	}

	return false, comparator.CompareWithNames(params[0], params[1], names[0], names[1])
}

// DeepEqual tests whether two parameters are deeply equal, and returns true if
// they are. If the objects are not deeply equal, then the second return value
// includes a json representation of the difference between the parameters.
func DeepEqual(params ...interface{}) (bool, string) {
	return DeepEquals.Check(params, defaultParams)
}

type cmpChecker struct {
	*check.CheckerInfo
}

// Equals is a GoCheck checker that does a diff between two objects and
// pretty-prints any difference between the two. It can act as a substitute
// for DeepEquals.
var (
	cmpParams               = []string{"obtained", "expected"}
	Equals    check.Checker = &cmpChecker{
		&check.CheckerInfo{Name: "Equals", Params: cmpParams},
	}
)

// Check performs a diff between two objects provided as parameters, and
// returns either true if the objects are identical, or false otherwise. If
// it returns false, it also returns the unified diff between the expected
// and obtained output.
func (checker *cmpChecker) Check(params []interface{}, _ []string) (result bool, error string) {
	if len(params) < 2 {
		return false, "Parameter missing"
	}

	// Diff expects to receive parameters in order ("expected",
	// "obtained"), but our convention is to pass them as
	// ("obtained", "expected"), so reverse them here.
	diff := cmp.Diff(params[1], params[0], DeepAllowUnexported(params[1], params[0]))

	return diff == "", diff
}

// Equal tests whether two parameters are deeply equal, and returns true if
// they are. If the objects are not deeply equal, then the second return value
// includes a json representation of the difference between the parameters.
func Equal(params ...interface{}) (bool, string) {
	return Equals.Check(params, cmpParams)
}

func DeepAllowUnexported(vs ...interface{}) cmp.Option {
	m := make(map[reflect.Type]struct{})
	for _, v := range vs {
		structTypes(reflect.ValueOf(v), m)
	}
	typs := make([]interface{}, 0, len(m))
	for t := range m {
		typs = append(typs, reflect.New(t).Elem().Interface())
	}
	return cmp.AllowUnexported(typs...)
}

func structTypes(v reflect.Value, m map[reflect.Type]struct{}) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			structTypes(v.Elem(), m)
		}
	case reflect.Interface:
		if !v.IsNil() {
			structTypes(v.Elem(), m)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			structTypes(v.Index(i), m)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			structTypes(v.MapIndex(k), m)
		}
	case reflect.Struct:
		m[v.Type()] = struct{}{}
		for i := 0; i < v.NumField(); i++ {
			structTypes(v.Field(i), m)
		}
	}
}

type cmpExportedChecker struct {
	*check.CheckerInfo
}

// ExportedEquals is a GoCheck checker that does a diff between two objects and
// pretty-prints any difference between the two. Note that unexported struct
// fields are NOT included in the comparison! Equals can act as a substitute
// for DeepEquals with the exception that unexported struct fields are ignored.
var ExportedEquals check.Checker = &cmpExportedChecker{&check.CheckerInfo{Name: "ExportedEquals", Params: cmpParams}}

// Check performs a diff between two objects provided as parameters, and
// returns either true if the objects are identical, or false otherwise. If
// it returns false, it also returns the unified diff between the expected
// and obtained output.
func (checker *cmpExportedChecker) Check(params []interface{}, _ []string) (result bool, error string) {
	if len(params) < 2 {
		return false, "Parameter missing"
	}

	// Diff expects to receive parameters in order ("expected",
	// "obtained"), but our convention is to pass them as
	// ("obtained", "expected"), so reverse them here.
	diff := cmp.Diff(params[1], params[0], DeepIgnoreUnexported(params[1], params[0]))

	return diff == "", diff
}

// ExportedEqual tests whether two parameters are deeply equal, when considering
// only exported fields, and returns true if they are. If the objects are not
// deeply equal, then the second return value includes a json representation of
// the difference between the parameters.
func ExportedEqual(params ...interface{}) (bool, string) {
	return ExportedEquals.Check(params, cmpParams)
}

func DeepIgnoreUnexported(vs ...interface{}) cmp.Option {
	m := make(map[reflect.Type]struct{})
	for _, v := range vs {
		exportedStructTypes(reflect.ValueOf(v), m)
	}
	typs := make([]interface{}, 0, len(m))
	for t := range m {
		typs = append(typs, reflect.New(t).Elem().Interface())
	}
	return cmpopts.IgnoreUnexported(typs...)
}

func exportedStructTypes(v reflect.Value, m map[reflect.Type]struct{}) {
	exportedUniqueStructTypes(v, m, make(map[uintptr]struct{}))
}

func exportedUniqueStructTypes(v reflect.Value, m map[reflect.Type]struct{}, s map[uintptr]struct{}) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			addr := v.Pointer()
			if _, found := s[addr]; found {
				return // prevent infinite loops
			}
			// mark pointer as seen
			s[addr] = struct{}{}
			exportedUniqueStructTypes(v.Elem(), m, s)
		}
	case reflect.Interface:
		if !v.IsNil() {
			exportedUniqueStructTypes(v.Elem(), m, s)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			exportedUniqueStructTypes(v.Index(i), m, s)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			exportedUniqueStructTypes(v.MapIndex(k), m, s)
		}
	case reflect.Struct:
		// mark type's unexported fields to be ignored
		m[v.Type()] = struct{}{}
		for i := 0; i < v.NumField(); i++ {
			// Only descend to exported fields
			if v.Field(i).CanInterface() {
				exportedUniqueStructTypes(v.Field(i), m, s)
			}
		}
	}
}

type matchesChecker struct {
	*check.CheckerInfo
}

// PartialMatches is a GoCheck checker that the provided regex matches at least
// part of the provided string. It can act as a substitute for Matches.
var (
	matchesParams                = []string{"value", "regex"}
	PartialMatches check.Checker = &matchesChecker{
		&check.CheckerInfo{Name: "PartialMatches", Params: matchesParams},
	}
)

// Check performs a regular expression search on the expression provided as the
// second parameter and the value provided as the first parameter. It returns
// true if the value matches the expression, otherwise it returns false.
func (checker *matchesChecker) Check(params []interface{}, _ []string) (result bool, error string) {
	if len(params) < 2 {
		return false, "Parameter missing"
	}

	valueStr, ok := params[0].(string)
	if !ok {
		return false, "Value must be a string"
	}
	regexStr, ok := params[1].(string)
	if !ok {
		return false, "Regex must be a string"
	}
	matches, err := regexp.MatchString(regexStr, valueStr)
	if err != nil {
		return false, "Failed to compile regex: " + err.Error()
	}
	return matches, ""
}

// -----------------------------------------------------------------------
// HasKey checker.

type hasKeyChecker struct {
	*check.CheckerInfo
}

// The HasKey checker verifies that the obtained map contains the
// provided key.
//
// For example:
//
//	c.Assert(myMap, HasKey, "five")
var HasKey check.Checker = &hasKeyChecker{
	&check.CheckerInfo{Name: "HasKey", Params: []string{"map", "key"}},
}

func (checker *hasKeyChecker) Check(params []interface{}, names []string) (result bool, error string) {
	if len(params) != 2 || len(names) != 2 {
		return false, "params and names must be of length 2"
	}

	m := reflect.ValueOf(params[0])
	mType := m.Type()
	key := reflect.ValueOf(params[1])
	keyType := key.Type()

	if mType.Kind() != reflect.Map {
		return false, fmt.Sprintf("'%s' must be a map", names[0])
	}
	if mType.Key() != keyType {
		return false, fmt.Sprintf("'%s' must be of '%s's key type (%s, not %s)",
			names[1], names[0], mType.Key(), keyType)
	}
	for _, v := range m.MapKeys() {
		if v.Interface() == key.Interface() {
			return true, ""
		}
	}
	return false, fmt.Sprintf("'%s' has no key %v", names[0], key.Interface())
}

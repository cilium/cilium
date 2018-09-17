// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package regexpmap

import (
	"regexp"
	"sort"
)

// lookupValueSet is a utility type. It is intended as a set of strings
// inserted into a RegexpMap
type lookupValueSet map[string]struct{}

// RegexpMap is a map-like type that allows lookups to match regexp keys. These
// keys are managed internally as strings, and are uniqued by this
// representation (and not recompiled on repeat inserts).
// Stored values are strings for simplicity but switching to a more generic
// type is possible, with the exception of output Uniqueing in Lookup.
// Note: RegexpMap is not thread-safe and managing concurrent access is the
// responsibility of the callers.
// Note: Simple DNS names, e.g. bar.foo.com, will treat the "." as a literal.
// Use .{1} to indicate a single wildcard character.
type RegexpMap struct {
	lookups map[string]lookupValueSet
	rules   map[string]*regexp.Regexp
}

// NewRegexpMap returns an initialized RegexpMap
func NewRegexpMap() *RegexpMap {
	return &RegexpMap{
		lookups: make(map[string]lookupValueSet),
		rules:   make(map[string]*regexp.Regexp),
	}
}

// Add associates lookupValue as a return value for reStr on lookup
// Repeat calls with the same reStr will not recompile the regexp, but will
// store lookupValue in a set
func (m *RegexpMap) Add(reStr string, lookupValue string) error {
	reStr = EscapeSimpleFQDN(reStr)

	if _, exists := m.rules[reStr]; !exists {
		rule, err := regexp.Compile(reStr)
		if err != nil {
			return err
		}
		m.rules[reStr] = rule
		m.lookups[reStr] = lookupValueSet{}
	}

	m.lookups[reStr][lookupValue] = struct{}{}

	return nil
}

// Lookup returns all lookupValues, inserted via Add, where the reStr key
// matches s
func (m *RegexpMap) Lookup(s string) (lookupValues []string) {
	for key, rule := range m.rules {
		if !rule.MatchString(s) {
			continue
		}
		for lookupValue := range m.lookups[key] {
			lookupValues = append(lookupValues, lookupValue)
		}
	}
	return keepUniqueStrings(lookupValues)
}

// Remove dissociates lookupValue from Lookups that match reStr. When no
// lookupValues remain for reStr the internall regexp is deleted (later Adds
// will recompile it).
func (m *RegexpMap) Remove(reStr, lookupValue string) (deleted bool) {
	reStr = EscapeSimpleFQDN(reStr)

	if _, exists := m.rules[reStr]; !exists {
		return false
	}
	delete(m.lookups[reStr], lookupValue)
	if len(m.lookups[reStr]) > 0 {
		return false
	}
	// clean everything up
	delete(m.lookups, reStr)
	delete(m.rules, reStr)
	return true
}

// keepUniqueStrings deduplicates strings in s. The output is sorted.
func keepUniqueStrings(s []string) []string {
	sort.Strings(s)

	out := s[:0] // len==0 but cap==cap(ips)
	for readIdx, str := range s {
		if len(out) == 0 ||
			out[len(out)-1] != s[readIdx] {
			out = append(out, str)
		}
	}

	return out
}

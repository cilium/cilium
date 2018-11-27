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
// inserted into a RegexpMap. Lookups are mapped to number of times
// they were added to map.
type lookupValueSet map[string]int

// RegexpMap is a map-like type that allows lookups to match regexp keys. These
// keys are managed internally as strings, and are uniqued by this
// representation (and not recompiled on repeat inserts).
// Stored values are strings and are returned as-is, with the exception that
// repeat inserts of the same value are de-duped.
// Note: RegexpMap is not thread-safe and managing concurrent access is the
// responsibility of the callers.
type RegexpMap struct {
	// lookups maps the original key string to the values added with it in .Add.
	// These values are returned when a "key" (the matching regex in rules)
	// matches.
	lookups map[string]lookupValueSet
	// rules maps the original key string to the compiled regex for it. A .Lookup
	// call will iterate over all the values in this map.
	rules map[string]*regexp.Regexp
}

// NewRegexpMap returns an initialized RegexpMap
func NewRegexpMap() *RegexpMap {
	return &RegexpMap{
		lookups: make(map[string]lookupValueSet),
		rules:   make(map[string]*regexp.Regexp),
	}
}

// Add associates lookupValue as a return value for reStr on lookup
// Repeated calls with the same reStr will not recompile the regexp, but will
// store all lookupValues in a set
func (m *RegexpMap) Add(reStr string, lookupValue string) error {
	// if this is the first Add of reStr, compile the regexp and setup the
	// lookupValue set
	if _, exists := m.rules[reStr]; !exists {
		rule, err := regexp.Compile(reStr)
		if err != nil {
			return err
		}
		m.rules[reStr] = rule
		m.lookups[reStr] = lookupValueSet{}
	}

	// add the lookupValue to the set for reStr
	m.lookups[reStr][lookupValue]++

	return nil
}

// LookupValues returns all lookupValues, inserted via Add, where the reStr
// matches lookupKey
func (m *RegexpMap) LookupValues(lookupKey string) (lookupValues []string) {
	for reStr, rule := range m.rules {
		if !rule.MatchString(lookupKey) {
			continue
		}
		for lookupValue := range m.lookups[reStr] {
			lookupValues = append(lookupValues, lookupValue)
		}
	}
	return keepUniqueStrings(lookupValues)
}

// LookupContainsValue returns true if any reStr in lookups, inserted via Add,
// matches lookupKey AND has a lookupValue, inserted via the same Add, that
// matches expectedValue.
func (m *RegexpMap) LookupContainsValue(lookupKey, expectedValue string) (found bool) {
	for reStr, rule := range m.rules {
		if !rule.MatchString(lookupKey) {
			continue
		}

		// The values are stored as a set, so a simple map lookup works.
		// The double lookup here is safe because it seems to short-circuits when
		// reStr is not present. The value in that case, which we don't use anyway,
		// is an empty struct{}.
		// Note: Lookups on nil maps work, hence the unguarded double lookup here.
		// If reStr is not in m.lookups, the second lookup for expectedValue is
		// also found==false.
		if _, found := m.lookups[reStr][expectedValue]; found {
			return true
		}
	}
	return false
}

// Remove dissociates lookupValue from Lookups that match reStr. When no
// lookupValues remain for reStr the internall regexp is deleted (later Adds
// will recompile it).
func (m *RegexpMap) Remove(reStr, lookupValue string) (deleted bool) {
	if _, exists := m.rules[reStr]; !exists {
		return false
	}

	if m.lookups[reStr][lookupValue] > 0 {
		m.lookups[reStr][lookupValue]--
	}
	if m.lookups[reStr][lookupValue] == 0 {
		delete(m.lookups[reStr], lookupValue)
	}
	if len(m.lookups[reStr]) > 0 {
		// there are still references to this lookup so we do not clean it up below
		return false
	}

	// clean everything up
	delete(m.lookups, reStr)
	delete(m.rules, reStr)
	return true
}

// GetPrecompiledRegexp returns the regexp matching reStr if it is in the map.
// This is a utility function to avoid recompiling regexps repeatedly, and the
// RegexpMap keeps the refcount for us.
func (m *RegexpMap) GetPrecompiledRegexp(reStr string) (re *regexp.Regexp) {
	return m.rules[reStr]
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

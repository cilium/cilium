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

// RegexpList is a utility struct that keeps an array of strings sorted by
// length
type RegexpList struct {
	data []string
}

// NewRegexpList returns a new RegexpList, if any initialValues is in place
// will add into the utility.
func NewRegexpList(initialValues ...string) *RegexpList {
	data := []string{}

	for _, x := range initialValues {
		data = append(data, x)
	}

	sort.Slice(data, func(i, j int) bool {
		return len(data[i]) < len(data[j])
	})

	return &RegexpList{
		data: data,
	}
}

// Add function adds a new item in the list and sort the data based on the
// length
func (r *RegexpList) Add(val string) {
	for _, item := range r.data {
		if item == val {
			return
		}
	}

	tmpData := append(r.data, val)

	sort.Slice(tmpData, func(i, j int) bool {
		return len(tmpData[i]) < len(tmpData[j])
	})

	r.data = tmpData
	return
}

// Remove removes the item from the internal array and keep the data sorted
func (r *RegexpList) Remove(val string) {
	tmpData := []string{}
	for _, item := range r.data {
		if item == val {
			continue
		}
		tmpData = append(tmpData, item)
	}

	r.data = tmpData
	return
}

// Empty empties the internal array
func (r *RegexpList) Empty() {
	r.data = []string{}
}

// Get return an array of strings ordered by string len
func (r *RegexpList) Get() []string {
	return r.data
}

// Len returns the len of the internal array.
func (r *RegexpList) Len() int {
	return len(r.data)
}

// RegexpMap is a map-like type that allows lookups to match regexp keys. These
// keys are managed internally as strings, and are uniqued by this
// representation (and not recompiled on repeat inserts).
// Stored values are strings and are returned as-is, with the exception that
// repeat inserts of the same value are de-duped.
// Note: RegexpMap is not thread-safe and managing concurrent access is the
// responsibility of the callers.
type RegexpMap struct {

	// lookupValues is a map that use a lookupValue as a key and has a
	// RegexpList with the rules that ONLY affect that lookupValue
	lookupValues map[string]*RegexpList

	// rules is a map that use a regular expression as a key and the value is
	// the compiled regexp
	rules map[string]*regexp.Regexp

	// rulesRelation is a map that use a regular expression as a key and the
	// values are all the lookupValues that has used this rule.
	rulesRelation map[string]*RegexpList
}

// NewRegexpMap returns an initialized RegexpMap
func NewRegexpMap() *RegexpMap {
	return &RegexpMap{
		lookupValues:  make(map[string]*RegexpList),
		rules:         make(map[string]*regexp.Regexp),
		rulesRelation: make(map[string]*RegexpList),
	}
}

// Add associates a Regular expression to a lookupValue that will be used in
// the lookup functions. It will return an error and data will be not saved if
// the regexp does not compile correctly
func (m *RegexpMap) Add(reStr string, lookupValue string) error {
	_, exists := m.rules[reStr]
	if !exists {
		rule, err := regexp.Compile(reStr)
		if err != nil {
			return err
		}
		m.rules[reStr] = rule
	}

	val, exists := m.lookupValues[lookupValue]
	if !exists {
		val = NewRegexpList()
		m.lookupValues[lookupValue] = val
	}
	val.Add(reStr)

	val, exists = m.rulesRelation[reStr]
	if !exists {
		val = NewRegexpList()
		m.rulesRelation[reStr] = val
	}
	val.Add(lookupValue)
	return nil
}

// LookupValues returns all lookupValues, inserted via Add, where the reStr
// matches lookupKey
func (m *RegexpMap) LookupValues(lookupKey string) (lookupValues []string) {
	for reStr, rule := range m.rules {

		if !rule.MatchString(lookupKey) {
			continue
		}

		val, exists := m.rulesRelation[reStr]
		if exists {
			lookupValues = append(lookupValues, val.Get()...)
		}
	}
	return keepUniqueStrings(lookupValues)
}

// LookupContainsValue returns true if any reStr in lookups, inserted via Add,
// matches lookupKey AND has a lookupValue, inserted via the same Add, that
// matches expectedValue.
func (m *RegexpMap) LookupContainsValue(lookupKey, expectedValue string) (found bool) {
	val, exists := m.lookupValues[expectedValue]
	if !exists {
		return false
	}

	for _, item := range val.Get() {
		rule := m.rules[item]
		if rule != nil {
			if rule.MatchString(lookupKey) {
				return true
			}
		}
	}
	return false
}

// Remove dissociates lookupValue from Lookups that match reStr. When no
// lookupValues remain for reStr the internall regexp is deleted (later Adds
// will recompile it).
func (m *RegexpMap) Remove(reStr, lookupValue string) (deleted bool) {

	val, exists := m.lookupValues[lookupValue]
	if exists {
		val.Remove(reStr)
	}

	val, exists = m.rulesRelation[reStr]
	if !exists {
		delete(m.rules, reStr)
		return true
	}

	val.Remove(lookupValue)
	if val.Len() == 0 {
		delete(m.rules, reStr)
	}
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

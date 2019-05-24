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
type RegexpList []string

// NewRegexpList returns a new RegexpList, if any initialValues is in place
// will add into the utility.
func NewRegexpList(initialValues ...string) (result *RegexpList) {
	sort.Slice(initialValues, func(i, j int) bool {
		return len(initialValues[i]) < len(initialValues[j])
	})

	tmp := RegexpList(initialValues)
	return &tmp
}

// Add function adds a new item in the list and sort the data based on the
// length
func (r *RegexpList) Add(val string) {
	for _, item := range *r {
		if item == val {
			return
		}
	}

	tmpData := append(*r, val)

	sort.Slice(tmpData, func(i, j int) bool {
		return len(tmpData[i]) < len(tmpData[j])
	})

	*r = tmpData
}

// Remove removes the item from the internal array and keep the data sorted
func (r *RegexpList) Remove(val string) {
	tmpData := []string{}
	for _, item := range *r {
		if item == val {
			continue
		}
		tmpData = append(tmpData, item)
	}
	*r = tmpData
	return
}

// Get return an array of strings ordered by string len
func (r *RegexpList) Get() []string {
	return *r
}

// Len returns the len of the internal array.
func (r *RegexpList) Len() int {
	return len(*r)
}

// refCount is a map alias that has a specific options for reference counts
type refCount map[string]int

// Increment adds one to the given key
func (r refCount) Increment(key string) int {
	r[key]++
	return r[key]
}

// Decrement remove one to the given key. If the value is 0, the key will be
// deleted.
func (r refCount) Decrement(key string) int {
	val := r[key]
	if val <= 1 {
		delete(r, key)
		return 0
	}
	r[key]--
	return r[key]
}

// Keys return the list of keys that are in place.
func (r refCount) Keys() []string {
	result := make([]string, len(r))
	position := 0
	for key := range r {
		result[position] = key
		position++
	}
	return result
}

// // Len returns the len of the inner map
// func (r refCount) Len() int {
// 	return len(r)
// }

// RegexpMap is a map-like type that allows lookups to match regexp keys. These
// keys are managed internally as strings, and are uniqued by this
// representation (and not recompiled on repeat inserts).
// Stored values are strings and are returned as-is, with the exception that
// repeat inserts of the same value are de-duped.
// Note: RegexpMap is not thread-safe and managing concurrent access is the
// responsibility of the callers.
type RegexpMap struct {

	// lookupValues is a map that use a lookupValue as a key and has a
	// RegexpList with the stringToRegExp that ONLY affect that lookupValue
	lookupValues map[string]*RegexpList

	// stringToRegExp is a map that use a regular expression as a key and the value is
	// the compiled regexp
	stringToRegExp map[string]*regexp.Regexp

	// regexRefCount is a map that use a regular expression as a key and the
	// values are all the lookupValues that has used this rule. To be able to
	// support duplicates we use a refcount type to be able to increment and
	// decrement the use.
	regexRefCount map[string]refCount
}

// NewRegexpMap returns an initialized RegexpMap
func NewRegexpMap() *RegexpMap {
	return &RegexpMap{
		lookupValues:   make(map[string]*RegexpList),
		stringToRegExp: make(map[string]*regexp.Regexp),
		regexRefCount:  make(map[string]refCount),
	}
}

// Add associates a Regular expression to a lookupValue that will be used in
// the lookup functions. It will return an error and data will be not saved if
// the regexp does not compile correctly
func (m *RegexpMap) Add(reStr string, lookupValue string) error {
	_, exists := m.stringToRegExp[reStr]
	if !exists {
		rule, err := regexp.Compile(reStr)
		if err != nil {
			return err
		}
		m.stringToRegExp[reStr] = rule
	}
	val, exists := m.lookupValues[lookupValue]
	if !exists {
		val = NewRegexpList()
		m.lookupValues[lookupValue] = val
	}
	val.Add(reStr)

	lookupCount, exists := m.regexRefCount[reStr]
	if !exists {
		lookupCount = refCount{}
		m.regexRefCount[reStr] = lookupCount
	}
	lookupCount.Increment(lookupValue)
	return nil
}

// LookupValues returns all lookupValues, inserted via Add, where the reStr
// matches lookupKey
func (m *RegexpMap) LookupValues(lookupKey string) (lookupValues []string) {
	for reStr, rule := range m.stringToRegExp {

		if !rule.MatchString(lookupKey) {
			continue
		}
		val, exists := m.regexRefCount[reStr]
		if exists {
			lookupValues = append(lookupValues, val.Keys()...)
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
		rule := m.stringToRegExp[item]
		if rule != nil && rule.MatchString(lookupKey) {
			return true
		}
	}
	return false
}

// Remove dissociates lookupValue from Lookups that match reStr. When no
// lookupValues remain for reStr the internall regexp is deleted (later Adds
// will recompile it).
func (m *RegexpMap) Remove(reStr, lookupValue string) (deleted bool) {
	lookupRelation, exists := m.regexRefCount[reStr]
	if !exists {
		return false
	}

	if lookupRelation.Decrement(lookupValue) > 0 {
		return false
	}

	// Making sure that no other stringToRegExp for the same reStr are in place.
	if len(lookupRelation) > 0 {
		return false
	}

	val, exists := m.lookupValues[lookupValue]
	if exists {
		val.Remove(reStr)
	}

	delete(m.stringToRegExp, reStr)
	delete(m.regexRefCount, reStr)
	return true
}

// GetPrecompiledRegexp returns the regexp matching reStr if it is in the map.
// This is a utility function to avoid recompiling regexps repeatedly, and the
// RegexpMap keeps the refcount for us.
func (m *RegexpMap) GetPrecompiledRegexp(reStr string) (re *regexp.Regexp) {
	return m.stringToRegExp[reStr]
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

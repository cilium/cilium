// Copyright 2021 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0
//

package object

import (
	"hash/fnv"
	"sort"
	"strconv"
)

// ObjMetadataSet is an ordered list of ObjMetadata that acts like an unordered
// set for comparison purposes.
type ObjMetadataSet []ObjMetadata

// UnstructuredSetEquals returns true if the slice of objects in setA equals
// the slice of objects in setB.
func ObjMetadataSetEquals(setA []ObjMetadata, setB []ObjMetadata) bool {
	return ObjMetadataSet(setA).Equal(ObjMetadataSet(setB))
}

// ObjMetadataSetFromMap constructs a set from a map
func ObjMetadataSetFromMap(mapA map[ObjMetadata]struct{}) ObjMetadataSet {
	setA := make(ObjMetadataSet, 0, len(mapA))
	for f := range mapA {
		setA = append(setA, f)
	}
	return setA
}

// Equal returns true if the two sets contain equivalent objects. Duplicates are
// ignored.
// This function satisfies the cmp.Equal interface from github.com/google/go-cmp
func (setA ObjMetadataSet) Equal(setB ObjMetadataSet) bool {
	mapA := make(map[ObjMetadata]struct{}, len(setA))
	for _, a := range setA {
		mapA[a] = struct{}{}
	}
	mapB := make(map[ObjMetadata]struct{}, len(setB))
	for _, b := range setB {
		mapB[b] = struct{}{}
	}
	if len(mapA) != len(mapB) {
		return false
	}
	for b := range mapB {
		if _, exists := mapA[b]; !exists {
			return false
		}
	}
	return true
}

// Contains checks if the provided ObjMetadata exists in the set.
func (setA ObjMetadataSet) Contains(id ObjMetadata) bool {
	for _, om := range setA {
		if om == id {
			return true
		}
	}
	return false
}

// Remove the object from the set and return the updated set.
func (setA ObjMetadataSet) Remove(obj ObjMetadata) ObjMetadataSet {
	for i, a := range setA {
		if a == obj {
			setA[len(setA)-1], setA[i] = setA[i], setA[len(setA)-1]
			return setA[:len(setA)-1]
		}
	}
	return setA
}

// Intersection returns the set of unique objects in both set A and set B.
func (setA ObjMetadataSet) Intersection(setB ObjMetadataSet) ObjMetadataSet {
	var maxlen int
	if len(setA) > len(setB) {
		maxlen = len(setA)
	} else {
		maxlen = len(setB)
	}
	mapI := make(map[ObjMetadata]struct{}, maxlen)
	mapB := setB.ToMap()
	for _, a := range setA {
		if _, ok := mapB[a]; ok {
			mapI[a] = struct{}{}
		}
	}
	intersection := make(ObjMetadataSet, 0, len(mapI))
	// Iterate over setA & setB to retain input order and have stable output
	for _, id := range setA {
		if _, ok := mapI[id]; ok {
			intersection = append(intersection, id)
			delete(mapI, id)
		}
	}
	for _, id := range setB {
		if _, ok := mapI[id]; ok {
			intersection = append(intersection, id)
			delete(mapI, id)
		}
	}
	return intersection
}

// Union returns the set of unique objects from the merging of set A and set B.
func (setA ObjMetadataSet) Union(setB ObjMetadataSet) ObjMetadataSet {
	m := make(map[ObjMetadata]struct{}, len(setA)+len(setB))
	for _, a := range setA {
		m[a] = struct{}{}
	}
	for _, b := range setB {
		m[b] = struct{}{}
	}
	union := make(ObjMetadataSet, 0, len(m))
	// Iterate over setA & setB to retain input order and have stable output
	for _, id := range setA {
		if _, ok := m[id]; ok {
			union = append(union, id)
			delete(m, id)
		}
	}
	for _, id := range setB {
		if _, ok := m[id]; ok {
			union = append(union, id)
			delete(m, id)
		}
	}
	return union
}

// Diff returns the set of objects that exist in set A, but not in set B (A - B).
func (setA ObjMetadataSet) Diff(setB ObjMetadataSet) ObjMetadataSet {
	// Create a map of the elements of A
	m := make(map[ObjMetadata]struct{}, len(setA))
	for _, a := range setA {
		m[a] = struct{}{}
	}
	// Remove from A each element of B
	for _, b := range setB {
		delete(m, b) // OK to delete even if b not in m
	}
	// Create/return slice from the map of remaining items
	diff := make(ObjMetadataSet, 0, len(m))
	// Iterate over setA to retain input order and have stable output
	for _, id := range setA {
		if _, ok := m[id]; ok {
			diff = append(diff, id)
			delete(m, id)
		}
	}
	return diff
}

// Unique returns the set with duplicates removed.
// Order may or may not remain consistent.
func (setA ObjMetadataSet) Unique() ObjMetadataSet {
	return ObjMetadataSetFromMap(setA.ToMap())
}

// Hash the objects in the set by serializing, sorting, concatonating, and
// hashing the result with the 32-bit FNV-1a algorithm.
func (setA ObjMetadataSet) Hash() string {
	objStrs := make([]string, 0, len(setA))
	for _, obj := range setA {
		objStrs = append(objStrs, obj.String())
	}
	sort.Strings(objStrs)
	h := fnv.New32a()
	for _, obj := range objStrs {
		// Hash32.Write never returns an error
		// https://pkg.go.dev/hash#pkg-types
		_, _ = h.Write([]byte(obj))
	}
	return strconv.FormatUint(uint64(h.Sum32()), 16)
}

// ToMap returns the set as a map, with objMeta keys and empty struct values.
func (setA ObjMetadataSet) ToMap() map[ObjMetadata]struct{} {
	m := make(map[ObjMetadata]struct{}, len(setA))
	for _, objMeta := range setA {
		m[objMeta] = struct{}{}
	}
	return m
}

// ToStringMap returns the set as a serializable map, with objMeta keys and
// empty string values.
func (setA ObjMetadataSet) ToStringMap() map[string]string {
	stringMap := make(map[string]string, len(setA))
	for _, objMeta := range setA {
		stringMap[objMeta.String()] = ""
	}
	return stringMap
}

// FromStringMap returns a set from a serializable map, with objMeta keys and
// empty string values. Errors if parsing fails.
func FromStringMap(in map[string]string) (ObjMetadataSet, error) {
	var set ObjMetadataSet
	for s := range in {
		objMeta, err := ParseObjMetadata(s)
		if err != nil {
			return nil, err
		}
		set = append(set, objMeta)
	}
	return set, nil
}

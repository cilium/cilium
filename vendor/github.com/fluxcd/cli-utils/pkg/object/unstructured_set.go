// Copyright 2021 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0
//

package object

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// UnstructuredSet is an ordered list of Unstructured that acts like an
// unordered set for comparison purposes.
type UnstructuredSet []*unstructured.Unstructured

// UnstructuredSetEquals returns true if the slice of objects in setA equals
// the slice of objects in setB.
func UnstructuredSetEquals(setA []*unstructured.Unstructured, setB []*unstructured.Unstructured) bool {
	return UnstructuredSet(setA).Equal(UnstructuredSet(setB))
}

func (setA UnstructuredSet) Equal(setB UnstructuredSet) bool {
	mapA := make(map[string]string, len(setA))
	for _, a := range setA {
		jsonBytes, err := a.MarshalJSON()
		if err != nil {
			mapA[string(jsonBytes)] = err.Error()
		} else {
			mapA[string(jsonBytes)] = ""
		}
	}
	mapB := make(map[string]string, len(setB))
	for _, b := range setB {
		jsonBytes, err := b.MarshalJSON()
		if err != nil {
			mapB[string(jsonBytes)] = err.Error()
		} else {
			mapB[string(jsonBytes)] = ""
		}
	}
	if len(mapA) != len(mapB) {
		return false
	}
	for b, errB := range mapB {
		if errA, exists := mapA[b]; !exists {
			if !exists {
				return false
			}
			if errA != errB {
				return false
			}
		}
	}
	return true
}

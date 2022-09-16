// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddSource(t *testing.T) {

	testSource := FullyQualifiedResource{
		Name:      "testSource",
		Namespace: "testNamespace",
		Group:     "group",
		Version:   "v1",
		Kind:      "Test",
	}

	emptySlice := []FullyQualifiedResource{}

	existsSlice := []FullyQualifiedResource{testSource}

	nonexistSlice := []FullyQualifiedResource{
		{
			Name: "SomeOtherResource",
		},
	}

	emptyOut := AddSource(emptySlice, testSource)
	assert.Equal(t, existsSlice, emptyOut)

	existsOut := AddSource(existsSlice, testSource)
	assert.Equal(t, existsSlice, existsOut)

	nonexistOut := AddSource(nonexistSlice, testSource)
	assert.Equal(t, append(nonexistSlice, testSource), nonexistOut)

}

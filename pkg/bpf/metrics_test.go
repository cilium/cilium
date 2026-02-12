// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type testMap struct {
	m *uint8
}

func (tm testMap) IsOpen() bool            { return false }
func (tm testMap) NonPrefixedName() string { return "" }
func (tm testMap) MaxEntries() uint32      { return 0 }

type testMapPtr struct {
	m *uint8
}

func (tm *testMapPtr) IsOpen() bool            { return false }
func (tm *testMapPtr) NonPrefixedName() string { return "" }
func (tm *testMapPtr) MaxEntries() uint32      { return 0 }

func TestValidMap(t *testing.T) {
	v := uint8(1)
	assert.Error(t, validProvidedMap(testMap{}))
	assert.NoError(t, validProvidedMap(testMap{&v}))

	assert.ErrorIs(t, validProvidedMap[*testMapPtr](nil), errMapDisabled)
	assert.NoError(t, validProvidedMap(&testMapPtr{}))
	assert.NoError(t, validProvidedMap(&testMapPtr{&v}))
}

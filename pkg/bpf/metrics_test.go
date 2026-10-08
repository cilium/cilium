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

func TestZeroValue(t *testing.T) {
	v := uint8(1)
	assert.Error(t, isZeroValue(testMap{}))
	assert.NoError(t, isZeroValue(testMap{&v}))

	assert.NoError(t, isZeroValue(&testMap{}))
	assert.NoError(t, isZeroValue(&testMap{&v}))

	assert.Error(t, isZeroValue(nil))
	assert.Error(t, isZeroValue((*testMap)(nil)))
}

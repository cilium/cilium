// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package registry

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapRegistry(t *testing.T) {
	reg, err := new(hivetest.Logger(t))
	require.NoError(t, err)

	// No get operations allowed, only modifications.
	_, err = reg.Get("foo")
	assert.ErrorIs(t, err, ErrNotStarted)
	_, err = reg.GetPatch("foo")
	assert.ErrorIs(t, err, ErrNotStarted)
	assert.ErrorIs(t, reg.Modify("foo", func(p *MapSpecPatch) {}), ErrMapNotFound)

	name1 := "cilium_calls"
	assert.NoError(t, reg.Modify(name1, func(p *MapSpecPatch) {
		p.MaxEntries = 1234
	}))

	// Start the registry, making it immutable.
	require.NoError(t, reg.start())

	// Get operations should now work, modifications should be rejected.
	_, err = reg.Get("foo")
	assert.ErrorIs(t, err, ErrMapNotFound)
	_, err = reg.GetPatch("foo")
	assert.ErrorIs(t, err, ErrMapNotFound)
	assert.ErrorIs(t, reg.Modify(name1, func(p *MapSpecPatch) {}), ErrStarted)

	// Verify that the patches were applied.
	spec1, err := reg.Get(name1)
	require.NoError(t, err)
	assert.Equal(t, name1, spec1.Name)
	assert.Equal(t, uint32(1234), spec1.MaxEntries)

	// Retrieve unmodified map.
	name2 := "cilium_metrics"
	spec2, err := reg.Get(name2)
	require.NoError(t, err)
	assert.Equal(t, name2, spec2.Name)

	// Retrieve patch.
	patch, err := reg.GetPatch(name1)
	require.NoError(t, err)
	assert.Equal(t, uint32(1234), patch.MaxEntries)

	// Try to retrieve patch for unmodified map.
	_, err = reg.GetPatch(name2)
	assert.ErrorIs(t, err, ErrMapNotFound)
}

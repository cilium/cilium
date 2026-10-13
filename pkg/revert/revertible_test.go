// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package revert

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type testRevertible struct {
	revert   func() error
	finalize func()
}

func (r testRevertible) Revert() error {
	return r.revert()
}

func (r testRevertible) Finalize() {
	r.finalize()
}

func TestRevertiblesIgnoreEmptyOperations(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value Revertible
	}{
		{"nil", nil},
		{"no-op", Noop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value != nil {
				for range 2 {
					require.NoError(t, tc.value.Revert())
					tc.value.Finalize()
				}
			}
			var revertibles Revertibles
			revertibles.Add(tc.value)
			require.True(t, revertibles.Empty())
			require.NoError(t, revertibles.Revert())
			revertibles.Finalize()
			require.Zero(t, testing.AllocsPerRun(100, func() {
				var revertibles Revertibles
				revertibles.Add(tc.value)
				revertibles.Finalize()
				_ = revertibles.Revert()
			}))
		})
	}
}

func TestRevertiblesFinalizeInForwardOrder(t *testing.T) {
	var completed []string
	var revertibles Revertibles
	revertibles.AddFinalize(func() { completed = append(completed, "finalize-only") })
	revertibles.Add(testRevertible{
		revert:   func() error { return nil },
		finalize: func() { completed = append(completed, "revertible") },
	})
	revertibles.AddRevert(func() error {
		completed = append(completed, "revert-only")
		return nil
	})

	revertibles.Finalize()
	require.Equal(t, []string{"finalize-only", "revertible"}, completed)
}

func TestRevertiblesRevertInReverseOrder(t *testing.T) {
	var completed []string
	var revertibles Revertibles
	revertibles.AddRevert(func() error {
		completed = append(completed, "revert-only")
		return nil
	})
	revertibles.Add(testRevertible{
		revert: func() error {
			completed = append(completed, "revertible")
			return nil
		},
		finalize: func() {},
	})
	revertibles.AddFinalize(func() { completed = append(completed, "finalize-only") })

	require.NoError(t, revertibles.Revert())
	require.Equal(t, []string{"revertible", "revert-only"}, completed)
}

func TestRevertiblesReturnRevertError(t *testing.T) {
	revertErr := errors.New("rollback failed")
	var revertibles Revertibles
	revertibles.Add(testRevertible{
		revert:   func() error { return revertErr },
		finalize: func() {},
	})

	err := revertibles.Revert()
	require.ErrorIs(t, err, revertErr)
}

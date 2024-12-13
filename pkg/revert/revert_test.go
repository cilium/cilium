// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package revert

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRevertStack(t *testing.T) {
	expectedContent := []string{"lmao", "ayy", "bar", "foo"}
	content := make([]string, 0, 4)
	rStack := RevertStack{}

	rStack.Push(func() error {
		content = append(content, "foo")
		return nil
	})
	rStack.Push(func() error {
		content = append(content, "bar")
		return nil
	})
	rStack.Push(func() error {
		content = append(content, "ayy")
		return nil
	})
	rStack.Push(func() error {
		content = append(content, "lmao")
		return nil
	})

	err := rStack.Revert()
	require.NoError(t, err)

	require.Equal(t, expectedContent, content)
}

func TestRevertStackError(t *testing.T) {
	var firstFuncCalled, secondFuncCalled, thirdFuncCalled bool
	rStack := RevertStack{}

	rStack.Push(func() error {
		firstFuncCalled = true
		return nil
	})
	rStack.Push(func() error {
		secondFuncCalled = true
		return errors.New("2nd function failed")
	})
	rStack.Push(func() error {
		thirdFuncCalled = true
		return nil
	})

	err := rStack.Revert()
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to execute revert function; skipping 1 revert functions: 2nd function failed")

	require.False(t, firstFuncCalled)
	require.True(t, secondFuncCalled)
	require.True(t, thirdFuncCalled)
}

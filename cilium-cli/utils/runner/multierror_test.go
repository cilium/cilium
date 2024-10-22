// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runner

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMultiError_no_errors(t *testing.T) {
	m := MultiError{}

	check := make([]int, 10)
	for i := 0; i < 10; i++ {
		id := i
		m.Go(func() error {
			check[id] = 1
			return nil
		})
	}

	require.NoError(t, m.Wait())
	for i := 0; i < 10; i++ {
		require.Equal(t, 1, check[i])
	}
}

func TestMultiError_with_errors(t *testing.T) {
	m := MultiError{}

	expectedErrs := []error{
		errors.New("error-1"),
		errors.New("error-2"),
		errors.New("error-3"),
		errors.New("error-4"),
		errors.New("error-5"),
	}
	for i := range expectedErrs {
		id := i
		m.Go(func() error {
			return expectedErrs[id]
		})
	}

	actualErr := m.Wait()
	actualErrStr := actualErr.Error()
	require.Error(t, actualErr)
	for i := range expectedErrs {
		require.True(t, errors.Is(actualErr, expectedErrs[i]))
		require.True(t, strings.Contains(actualErrStr, expectedErrs[i].Error()))
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runner

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMultiError_no_errors(t *testing.T) {
	m := MultiError{}

	check := make([]int, 10)
	for i := range 10 {
		id := i
		m.Go(func() error {
			check[id] = 1
			return nil
		})
	}

	require.NoError(t, m.Wait())
	for i := range 10 {
		require.Equal(t, 1, check[i])
	}
}

func TestMultiError_on_error_fires_before_wait(t *testing.T) {
	m := MultiError{}

	reported := make(chan error, 2)
	m.OnError = func(err error) { reported <- err }

	first := errors.New("error-1")
	blocked := make(chan struct{})
	m.Go(func() error { return first })
	m.Go(func() error {
		<-blocked
		return errors.New("error-2")
	})

	select {
	case got := <-reported:
		require.ErrorIs(t, got, first)
	case <-time.After(time.Minute):
		t.Fatal("OnError did not fire while a goroutine was still running")
	}

	close(blocked)
	require.Error(t, m.Wait())
	require.Len(t, reported, 1)
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
		require.ErrorIs(t, actualErr, expectedErrs[i])
		require.Contains(t, actualErrStr, expectedErrs[i].Error())
	}
}

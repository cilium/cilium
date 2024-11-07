// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package safenetlink

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/wait"
)

func Test_withRetryResult(t *testing.T) {
	// Test eventually successful
	retries := 0
	out, err := WithRetryResult(func() (string, error) {
		if retries < 3 {
			retries++
			return "", netlink.ErrDumpInterrupted
		}

		return "success", nil
	})
	require.NoError(t, err)
	require.Equal(t, "success", out)
	require.Equal(t, 3, retries)

	// Test eventually fails
	retries = 0
	out, err = WithRetryResult(func() (string, error) {
		if retries < 3 {
			retries++
			return "", netlink.ErrDumpInterrupted
		}

		return "failure", io.ErrUnexpectedEOF
	})
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, "failure", out)
	require.Equal(t, 3, retries)

	// Test eventually times out
	out, err = WithRetryResult(func() (string, error) {
		return "", netlink.ErrDumpInterrupted
	})
	require.True(t, wait.Interrupted(err))
	require.Empty(t, out)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostname(t *testing.T) {
	h, err := os.Hostname()

	// Unmodified node-name value is either os.Hostname if available or
	// "localhost" otherwise
	if err != nil {
		require.Equal(t, "localhost", GetName())
	} else {
		require.Equal(t, h, GetName())
	}

	newName := "foo.domain"
	SetName(newName)
	require.Equal(t, newName, GetName())
}

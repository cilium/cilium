// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryMap(t *testing.T) {
	pid := os.Getpid()
	m := memoryMap(pid)
	require.NotEmpty(t, m)
}

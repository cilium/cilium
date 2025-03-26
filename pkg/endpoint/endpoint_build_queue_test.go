// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMinimumWorkerThreadsIsSet(t *testing.T) {
	require.GreaterOrEqual(t, numWorkerThreads(), 2)
	require.GreaterOrEqual(t, numWorkerThreads(), runtime.NumCPU())
}

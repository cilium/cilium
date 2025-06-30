// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cleanup

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandleCleanup(t *testing.T) {
	wg := &sync.WaitGroup{}
	ch := make(chan struct{})
	i := 0
	DeferTerminationCleanupFunction(wg, ch, func() {
		i++
	})
	close(ch)
	wg.Wait()
	require.Equal(t, 1, i)
}

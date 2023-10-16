// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lock

import (
	"math/rand"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSortableMutex(t *testing.T) {
	smu1 := NewSortableMutex()
	smu2 := NewSortableMutex()
	require.Greater(t, smu2.Seq(), smu1.Seq())
	smu1.Lock()
	smu2.Lock()
	smu1.Unlock()
	smu2.Unlock()
	smus := SortableMutexes{smu1, smu2}
	smus.Lock()
	smus.Unlock()
	smus.Lock()
	smus.Unlock()
}

func TestSortableMutex_Chaos(t *testing.T) {
	smus := SortableMutexes{
		NewSortableMutex(),
		NewSortableMutex(),
		NewSortableMutex(),
		NewSortableMutex(),
		NewSortableMutex(),
	}

	nMonkeys := 10
	iterations := 100
	var wg sync.WaitGroup
	wg.Add(nMonkeys)

	monkey := func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			// Take a random subset of the sortable mutexes.
			subSmus := slices.Clone(smus)
			rand.Shuffle(len(subSmus), func(i, j int) {
				subSmus[i], subSmus[j] = subSmus[j], subSmus[i]
			})
			n := rand.Intn(len(subSmus))
			subSmus = subSmus[:n]

			time.Sleep(time.Microsecond)
			subSmus.Lock()
			time.Sleep(time.Microsecond)
			subSmus.Unlock()
			time.Sleep(time.Microsecond)
		}
	}

	for i := 0; i < nMonkeys; i++ {
		go monkey()
	}

	wg.Wait()
}

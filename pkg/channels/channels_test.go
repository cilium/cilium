// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package channels

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

func TestMergeNilSlice(t *testing.T) {
	defer goleak.VerifyNone(t)

	var chs []<-chan struct{}
	_, ok := <-Merge(chs...)
	assert.False(t, ok)
}

func TestMergeSingleChannel(t *testing.T) {
	defer goleak.VerifyNone(t)

	ch := make(chan struct{})
	chs := []<-chan struct{}{ch}
	merged := Merge(chs...)

	var (
		wg sync.WaitGroup
		ok bool
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, ok = <-merged
	}()

	close(ch)

	wg.Wait()
	assert.False(t, ok)
}

func TestMergeMultipleChannels(t *testing.T) {
	defer goleak.VerifyNone(t)

	ch1, ch2, ch3 := make(chan struct{}), make(chan struct{}), make(chan struct{})
	chs := []<-chan struct{}{ch1, ch2, ch3}
	merged := Merge(chs...)

	oks := make([]bool, len(chs))
	var wg sync.WaitGroup
	wg.Add(len(chs))
	for i := 0; i < len(chs); i++ {
		go func(ok *bool) {
			defer wg.Done()
			_, *ok = <-merged
		}(&oks[i])
	}

	close(ch1)
	close(ch2)
	close(ch3)

	wg.Wait()
	for i := 0; i < len(chs); i++ {
		assert.False(t, oks[i])
	}
}

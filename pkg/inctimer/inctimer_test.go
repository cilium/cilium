// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package inctimer

import (
	"testing"
	"time"
)

func TestTimerAfter(t *testing.T) {
	for i := 0; i < 100_000; i++ {
		tr, done := New()
		select {
		case <-tr.After(time.Second):
			t.Fatal("`IncTimer` fired too soon")
		default:
		}
		done()
	}
}

func TestTimerHardReset(t *testing.T) {
	tr, done := New()
	defer done()
	for i := 0; i < 100; i++ {
		select {
		case <-tr.After(time.Millisecond):
		case <-time.After(time.Millisecond * 2):
			t.Fatal("`IncTimer`, after being reset, did not fire")
		}
	}
}

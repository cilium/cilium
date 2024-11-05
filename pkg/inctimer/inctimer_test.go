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
		ch := tr.After(time.Millisecond)
		select {
		case <-ch:
		// Under CPU constrained environments, there may be a delay
		// between the timer firing and the goroutine being scheduled,
		case <-time.After(time.Millisecond * 2):
			select {
			case <-ch:
				t.Log("Warning: `IncTimer` eventually fired, but was delayed (this is likely caused by constrained CPU resources and GC)")
			case <-time.After(time.Millisecond * 2):
				t.Fatal("`IncTimer` did not fire after being reset")
			}
		}
	}
}

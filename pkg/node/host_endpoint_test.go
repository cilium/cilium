// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import "testing"

func TestEndpointIDAndWatch(t *testing.T) {
	previous, _ := GetEndpointID()
	t.Cleanup(func() { SetEndpointID(previous) })
	SetEndpointID(templateHostEndpointID)

	id, initialized, watch := GetEndpointIDAndWatch()
	if id != templateHostEndpointID || initialized {
		t.Fatalf("unexpected initial ID: id=%d initialized=%t", id, initialized)
	}
	assertEndpointIDWatchOpen(t, watch)

	// Every subscriber to this value must wake when allocation completes.
	_, _, secondWatch := GetEndpointIDAndWatch()
	SetEndpointID(517)
	assertEndpointIDWatchClosed(t, watch)
	assertEndpointIDWatchClosed(t, secondWatch)

	id, initialized, watch = GetEndpointIDAndWatch()
	if id != 517 || !initialized {
		t.Fatalf("unexpected allocated ID: id=%d initialized=%t", id, initialized)
	}
	assertEndpointIDWatchOpen(t, watch)

	// Re-publishing the same ID must not cause a regeneration loop.
	SetEndpointID(517)
	assertEndpointIDWatchOpen(t, watch)

	// Replacement of an already initialized host endpoint also wakes consumers.
	SetEndpointID(105)
	assertEndpointIDWatchClosed(t, watch)
	id, initialized, watch = GetEndpointIDAndWatch()
	if id != 105 || !initialized {
		t.Fatalf("unexpected replacement ID: id=%d initialized=%t", id, initialized)
	}
	assertEndpointIDWatchOpen(t, watch)
}

func TestEndpointIDAndWatchConcurrentUpdate(t *testing.T) {
	previous, _ := GetEndpointID()
	t.Cleanup(func() { SetEndpointID(previous) })

	for range 1000 {
		SetEndpointID(templateHostEndpointID)
		done := make(chan struct{})
		go func() {
			SetEndpointID(517)
			close(done)
		}()
		id, initialized, watch := GetEndpointIDAndWatch()
		<-done

		// Either we observed the new ID, or our old-value watch must have fired.
		if initialized {
			if id != 517 {
				t.Fatalf("unexpected initialized ID: %d", id)
			}
			assertEndpointIDWatchOpen(t, watch)
		} else {
			assertEndpointIDWatchClosed(t, watch)
		}
	}
}

func assertEndpointIDWatchOpen(t *testing.T, watch <-chan struct{}) {
	t.Helper()
	select {
	case <-watch:
		t.Fatal("host endpoint ID watch unexpectedly closed")
	default:
	}
}

func assertEndpointIDWatchClosed(t *testing.T, watch <-chan struct{}) {
	t.Helper()
	select {
	case <-watch:
	default:
		t.Fatal("host endpoint ID watch did not close")
	}
}
